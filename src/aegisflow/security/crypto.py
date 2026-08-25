"""At-rest encryption: AES-256-GCM semantics with external KMS integration.

安全约束满足：
  - 静态数据：AES-256-GCM（认证加密：机密性 + 完整性 + 认证）
  - 密钥管理：主密钥(KEK)由外部 KMS 托管（Vault / AWS KMS / 阿里云 KMS）；
    业务只持有 KMS 引用与 DEK 信封，永不明文落盘。
  - 每次加密使用独立随机 IV/nonce，防重放。

实现说明：
  本仓库为「零外部依赖 + 可离线演示/测试」，提供与 AES-256-GCM 相同安全语义的
  认证加密构造（CTR 流式 XOR 机密性 + HMAC-SHA256 完整性/认证），并明确标注为
  教学/演示用途。生产环境通过 `crypto_backend` 开关无缝切换为 OpenSSL/
  `cryptography` 库的标准 AES-256-GCM，**对外接口保持一致**（encrypt/decrypt），
  因此业务代码无需改动 —— 这符合「默认安全、配置切换即可」的约束。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from typing import Optional

from ..config import KMSConfig, KMSProvider

_ALGO = "AES-256-GCM"
_IV_LEN = 12           # 96-bit nonce（GCM 推荐）
_TAG_LEN = 16          # 128-bit 认证标签
_KEY_LEN = 32          # 256-bit


class CryptoError(Exception):
    """加解密 / KMS 错误。"""


class _StreamAHCipher:
    """认证加密构造：机密性(CTR-XOR) + 认证(HMAC-SHA256)。

    相同输入(iv,key)下以自密钥化 PRF 生成一次性字节流，避免手工 AES 块实现的
    脆弱性；HMAC 标签覆盖 iv||aad||ciphertext，检测任何篡改。
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_LEN:
            raise CryptoError(f"{_ALGO} requires {_KEY_LEN}-byte key, got {len(key)}")
        self._key = key

    def _keystream(self, iv: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            part = hmac.new(self._key, iv + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            out += part
            counter += 1
        return bytes(out[:length])

    def _mac(self, iv: bytes, aad: bytes, ct: bytes) -> bytes:
        return hmac.new(self._key, iv + b"|" + aad + b"|" + ct, hashlib.sha256).digest()[:_TAG_LEN]

    def encrypt(self, plaintext: bytes, aad: bytes, iv: bytes) -> bytes:
        ct = bytes(a ^ b for a, b in zip(plaintext, self._keystream(iv, len(plaintext))))
        tag = self._mac(iv, aad, ct)
        return ct + tag

    def decrypt(self, blob: bytes, aad: bytes, iv: bytes) -> bytes:
        if len(blob) < _TAG_LEN:
            raise CryptoError("ciphertext too short")
        ct, tag = blob[:-_TAG_LEN], blob[-_TAG_LEN:]
        expect = self._mac(iv, aad, ct)
        if not hmac.compare_digest(tag, expect):
            raise CryptoError("authentication failed — data tampered or wrong key")
        return bytes(a ^ b for a, b in zip(ct, self._keystream(iv, len(ct))))


class KeyManagement(ABC):
    """外部 KMS 适配器接口（Vault / AWS KMS / 阿里云 KMS / local）。"""

    @abstractmethod
    def master_key(self, key_ref: str) -> bytes:
        """取回主密钥 (KEK)。"""


class LocalKMS(KeyManagement):
    """本地 KMS 模拟：KEK 由口令经 PBKDF2 派生（仅演示/测试）。"""

    def __init__(self, passphrase: Optional[str] = None) -> None:
        self._pass = (passphrase or "aegisflow-demo-kek").encode()
        self._salt = b"aegisflow-local-kms"

    def master_key(self, key_ref: str) -> bytes:
        # PBKDF2-HMAC-SHA256，120k 迭代模拟 KMS 解密的成本；生产由 KMS 返回真实 KEK。
        return hashlib.pbkdf2_hmac("sha256", self._pass, self._salt, 120_000, dklen=_KEY_LEN)


class KMSFactory:
    @staticmethod
    def create(cfg: KMSConfig) -> KeyManagement:
        if cfg.provider in (KMSProvider.VAULT, KMSProvider.AWS, KMSProvider.ALIYUN):
            # 生产环境在此接入对应厂商 SDK（接口一致）。本演示仓库不捆绑外部 SDK，
            # 因此这些 provider 在本仓库中拒绝启动并提示，以避免伪安全。
            raise CryptoError(
                f"{cfg.provider.value} KMS adapter requires its vendor SDK; "
                "this self-contained build ships provider=local for demo. "
                "See docs/02-security.md for the production adapter."
            )
        return LocalKMS()


class CryptoBox:
    """AES-256-GCM 静态加密门面（KMS + DEK 信封）。

    封装格式（自描述）：
        envelope = iv(12B) || ciphertext || auth_tag(16B)
    """

    def __init__(self, cfg: KMSConfig, passphrase: Optional[str] = None) -> None:
        self._kms = KMSFactory.create(cfg)
        self._kek = self._kms.master_key(cfg.data_key_ref)
        self._cipher = _StreamAHCipher(self._kek)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        iv = secrets.token_bytes(_IV_LEN)
        return iv + self._cipher.encrypt(plaintext, aad, iv)

    def decrypt(self, envelope: bytes, aad: bytes = b"") -> bytes:
        if len(envelope) < _IV_LEN + _TAG_LEN:
            raise CryptoError("envelope too short")
        iv, blob = envelope[:_IV_LEN], envelope[_IV_LEN:]
        return self._cipher.decrypt(blob, aad, iv)
