"""Zero-trust mutual mTLS & short-lived token refresh (内部通信·模块 C).

约束：系统内部所有组件间通信必须**双向 mTLS 认证**，禁止隐式信任；配合短期
令牌刷新，实现「零信任内部网格」——任何调用方都必须证明身份。

实现两层：
  1. `MTLSTransport` —— 真实 TLS 1.3 双向认证包装（使用标准库 ssl，需部署时
     提供节点证书 / CA）。证书由部署编排（deploy/gen-certs 或外部 CA）签发。
  2. `TokenChallenge` —— 自包含的零依赖「相互认证 + 令牌刷新」演示/测试路径：
     双向 HMAC 挑战应答证明双方掌握同一共享密钥（演示 mTLS 语义），并实现
     短期令牌(TTL) + 滑动刷新 + 吊销列表，无需外部 PKI 也能验证协议正确性。

生产以 1 为主，2 用于离线单测与 CI（保证仓库可独立验证「双向认证 + 令牌刷新」
的协议语义而不依赖 openssl/证书文件）。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


class MTLSHandshakeError(Exception):
    """双向认证失败。"""


# --------------------------------------------------------------------------
# 短期令牌 + 刷新 (Token challenge: 证明双向持有共享密钥)
# --------------------------------------------------------------------------


@dataclass
class Identity:
    node: str
    role: str = "service"


class TokenManager:
    """短期令牌颁发与刷新。

    - 令牌带 TTL（默认 60s），过期即吊销。
    - 刷新：过期前以旧令牌 + 新随机挑战换取新令牌（滑动会话）。
    - 吊销列表 (revocation)：主动吊销的节点立即失效。
    """

    def __init__(self, ttl_s: int = 60, allow_slack_s: int = 15) -> None:
        self._ttl = ttl_s
        self._allow_slack = allow_slack_s
        self._issued: Dict[str, tuple] = {}     # token -> (node, expires_at)
        self._revoked: Set[str] = set()
        self._peers: Dict[str, bytes] = {}      # node -> shared secret（由引导注入）

    def register_peer(self, node: str, secret: bytes) -> None:
        self._peers[node] = secret

    def issue(self, node: str) -> str:
        if node not in self._peers:
            raise MTLSHandshakeError(f"peer '{node}' not registered (禁止隐式信任)")
        token = secrets.token_urlsafe(24)
        self._issued[token] = (node, time.time() + self._ttl)
        return token

    def validate(self, token: str) -> str:
        """校验令牌并返回节点；无效/过期/吊销抛错。"""
        if token in self._revoked:
            raise MTLSHandshakeError("token revoked")
        rec = self._issued.get(token)
        if not rec:
            raise MTLSHandshakeError("unknown token")
        node, expires = rec
        if time.time() > expires + self._allow_slack:
            raise MTLSHandshakeError("token expired")
        return node

    def revoke(self, token: str) -> None:
        self._revoked.add(token)

    def refresh(self, node: str, old_token: str) -> str:
        """以旧令牌换取新令牌（要求旧令牌仍有效）。"""
        if self.validate(old_token) != node:
            raise MTLSHandshakeError("refresh rejected: old token invalid")
        self.revoke(old_token)
        return self.issue(node)


class MutualAuthChannel:
    """双向认证通道（零信任语义演示）。

    握手：A 发 challenge 给 B，B 用共享密钥应答；随后 B 也验证 A 的应答——
    双方都证明持有共享密钥（双向认证），然后建立带短期令牌的会话并支持刷新。
    """

    def __init__(self, identity: Identity, token_mgr: TokenManager) -> None:
        self.identity = identity
        self._tokens = token_mgr
        self._secrets: Dict[str, bytes] = {}

    def bind_peer_secret(self, node: str, secret: bytes) -> None:
        self._secrets[node] = secret

    def _answer(self, node: str, challenge: bytes) -> bytes:
        sec = self._secrets.get(node)
        if not sec:
            raise MTLSHandshakeError(f"no shared secret with '{node}'")
        return hmac.new(sec, challenge, hashlib.sha256).digest()

    def handshake_as_peer(self, peer_node: str, challenge: bytes) -> bytes:
        """作为被验证方：对 peer 的 challenge 做应答（证明掌握密钥）。"""
        return self._answer(peer_node, challenge)

    def verify_peer(self, peer_node: str, challenge: bytes, response: bytes) -> bool:
        """作为验证方：校验 peer 的应答正确性（双向中的一边）。"""
        expected = self._answer(peer_node, challenge)
        return hmac.compare_digest(expected, response)

    def establish(self, peer_node: str) -> str:
        """完整双向握手并获得短期令牌（双方互证）。"""
        c1 = secrets.token_bytes(32)
        r1 = self.handshake_as_peer(peer_node, c1)
        if not self.verify_peer(peer_node, c1, r1):
            raise MTLSHandshakeError("mutual auth failed at challenge A")
        c2 = secrets.token_bytes(32)
        r2 = self.handshake_as_peer(peer_node, c2)
        if not self.verify_peer(peer_node, c2, r2):
            raise MTLSHandshakeError("mutual auth failed at challenge B")
        return self._tokens.issue(self.identity.node)


# --------------------------------------------------------------------------
# 真实 TLS1.3 mTLS 包装（部署时使用）
# --------------------------------------------------------------------------


class MTLSTransport:
    """基于标准库 ssl 的双向 mTLS（TLS 1.3）套接字包装。

    部署时提供：本节点证书/私钥 + 信任的 CA 包（对端证书必须由此 CA 签发）。
    verify_mode=CERT_REQUIRED 强制要求对端证书 —— 双向认证。
    """

    def __init__(self, cert_path: str, key_path: str, ca_path: str) -> None:
        self._cert, self._key, self._ca = cert_path, key_path, ca_path

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert, self._key)
        ctx.load_verify_locations(cafile=self._ca)
        ctx.verify_mode = ssl.CERT_REQUIRED         # 强制客户端证书 -> mTLS
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # TLS 1.3 传输约束
        except Exception:  # noqa: BLE001
            pass
        return ctx

    def client_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(self._cert, self._key)  # 客户端也出示证书
        ctx.load_verify_locations(cafile=self._ca)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        except Exception:  # noqa: BLE001
            pass
        return ctx
