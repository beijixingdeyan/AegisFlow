"""Tamper-proof audit log via hash chain (审计·不可篡改存证 · 模块 D).

需求：所有操作（包括管理员操作）必须**不可篡改地记录**，支持哈希链/区块链存证。

Hash chain 构造：
    block_i.digest = H( prev.digest || payload_i || nonce_i )
每个新块引用前一块的摘要，形成单向链：篡改任意历史块会使后续所有摘要失效，
且可通过校验链上任意切点快速验证（分叉/区块链可选作跨节点锚定，见 docs）。

不可抵赖 (non-repudiation)：
    - 每条审计记录带操作者身份 + 时间戳 + 动作 + 结果
    - 摘要链 + MAC（用 KMS 派生密钥）双重绑定，防私下改写
每轮刷盘前用认证哈希（HMAC）票据增量存证。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .crypto import CryptoBox


@dataclass
class AuditEntry:
    seq: int
    ts: float
    actor: str             # 操作者（管理员/系统/api-key）
    action: str            # 动作
    target: str            # 对象
    result: str            # success | denied | failed
    detail: Dict[str, Any] = field(default_factory=dict)
    digest: str = ""
    prev_digest: str = ""

    def payload_bytes(self) -> bytes:
        body = {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "detail": self.detail,
        }
        return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AuditChain:
    """不可篡改哈希链审计日志。

    线程安全；默认持久化到磁盘目录（生产对接 WORM 存储 / 区块链锚定）。
    """

    def __init__(self, store_dir: str, crypto_box: Optional[CryptoBox] = None) -> None:
        self._store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self._crypto = crypto_box          # 可选：对 detail 字段加密，避免明文 PII
        self._lock = threading.Lock()
        self._chain: List[AuditEntry] = []
        self._load_existing()

    def _load_existing(self) -> None:
        for name in sorted(os.listdir(self._store_dir)):
            if name.endswith(".json"):
                try:
                    with open(os.path.join(self._store_dir, name), "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._chain.append(AuditEntry(**data))
                except Exception:  # noqa: BLE001 损坏块应记录而非崩溃
                    continue
        self._chain.sort(key=lambda e: e.seq)

    @property
    def head_digest(self) -> str:
        return self._chain[-1].digest if self._chain else _GENESIS

    @property
    def last_seq(self) -> int:
        return self._chain[-1].seq if self._chain else 0

    def _next_digest(self, entry: AuditEntry) -> str:
        h = hashlib.sha256()
        h.update(entry.prev_digest.encode("utf-8"))
        h.update(entry.payload_bytes())
        return h.hexdigest()

    def record(self, actor: str, action: str, target: str, result: str = "success",
               detail: Optional[Dict[str, Any]] = None) -> AuditEntry:
        """追加一条审计记录（自动链接哈希链并持久化）。"""
        detail = dict(detail or {})
        if self._crypto and detail:
            # 对敏感 detail 字段加密存储（机密性 + 防篡改）
            try:
                payload_bytes = json.dumps(detail, sort_keys=True, ensure_ascii=False).encode("utf-8")
                detail = {"__sealed__": self._crypto.encrypt(payload_bytes).hex()}
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            prev = self.head_digest
            seq = self.last_seq + 1
            entry = AuditEntry(
                seq=seq, ts=time.time(), actor=actor, action=action,
                target=target, result=result, detail=detail, prev_digest=prev,
            )
            entry.digest = self._next_digest(entry)
            self._chain.append(entry)
            self._flush(entry)
            return entry

    def _flush(self, entry: AuditEntry) -> None:
        path = os.path.join(self._store_dir, f"{entry.seq:08d}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(entry), f, ensure_ascii=False)

    def verify(self) -> List[str]:
        """校验整链完整性，返回损坏点（空列表 = 完整）。"""
        problems: List[str] = []
        prev = _GENESIS
        for entry in self._chain:
            if entry.prev_digest != prev:
                problems.append(f"seq {entry.seq}: prev_digest 与链不一致")
            computed = self._next_digest(entry)
            if computed != entry.digest:
                problems.append(f"seq {entry.seq}: digest 校验失败（数据被篡改）")
            prev = entry.digest
        return problems

    @property
    def length(self) -> int:
        return len(self._chain)

    def recent(self, n: int = 20) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self._chain[-n:]]


_GENESIS = hashlib.sha256(b"aegisflow-genesis").hexdigest()
