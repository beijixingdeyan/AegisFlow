"""Data Plane: high-throughput event ingestion & normalization.

The Data Plane is responsible for: capture -> normalize -> publish to the
resilient bus. It is designed to be *stateless* (a horizontally scalable worker)
and to apply backpressure on a *per-source* basis so a hostile or noisy source
cannot starve legitimate telemetry (防噪声/防 DoS 语义)。

The ingestion layer transparency: any event source (network flow, EDR, identity
log, cloud trail, API gateway) is normalized to a common `Event` schema before
entering the detection pipeline — this is what lets AegisFlow ingest diverse
"signals" (不是单纯日志）into one behavior model.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..bus.resilient_queue import BackpressureBuffer


class NormalizationError(Exception):
    """Raised when a raw record cannot be normalized (schema/semantics)."""


@dataclass
class Event:
    """统一事件模型（Data Plane 传输单元，schema-first）。"""

    event_id: str
    ts: float                 # epoch seconds
    source: str               # 来源：edr / identity / flow / cloudtrail / api
    entity_id: str            # 行为主体：user / device / service_account / ip
    entity_type: str          # user | device | service | ip
    action: str               # 动作：login / exec / transfer / access ...
    outcome: str              # success | failure | denied
    features: Dict[str, float] = field(default_factory=dict)  # 数值特征
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)          # 原始载荷(脱敏后)
    risk_hint: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.ts,
            "source": self.source,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "action": self.action,
            "outcome": self.outcome,
            "features": self.features,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Event":
        return cls(
            event_id=d.get("event_id", uuid.uuid4().hex),
            ts=d.get("ts", time.time()),
            source=d.get("source", "unknown"),
            entity_id=d.get("entity_id", ""),
            entity_type=d.get("entity_type", "unknown"),
            action=d.get("action", ""),
            outcome=d.get("outcome", ""),
            features=dict(d.get("features", {})),
            tags=list(d.get("tags", [])),
            raw=d.get("raw", {}),
        )


# ------- Normalizers (per source) ------------------------------------------
# Each normalizer performs: schema mapping, type coercion, and *privacy-driven*
# field trimming (PII fields are dropped/redacted before reaching detection).

def _coerce_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


class Normalizer:
    """Base normalizer contract — pluggable per source."""

    def __init__(self, source: str) -> None:
        self.source = source

    def normalize(self, raw: Dict[str, Any]) -> Event:
        raise NotImplementedError

    # 脱敏：删除可能含 PII 的字段，避免明文进入检测模型/日志链
    _PII_FIELDS = ("username", "sso_email", "source_ip", "user_agent",
                   "hostname", "device_id", "file_path", "url", "command")

    @staticmethod
    def _redact(raw: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in raw.items() if k not in Normalizer._PII_FIELDS}


class IdentityNormalizer(Normalizer):
    """身份认证日志：登录成功/失败、地理位置、设备指纹等特征。"""

    def __init__(self) -> None:
        super().__init__("identity")

    def normalize(self, raw: Dict[str, Any]) -> Event:
        out = raw.get("outcome", "success")
        return Event(
            event_id=raw.get("event_id", uuid.uuid4().hex),
            ts=float(raw.get("ts", time.time())),
            source=self.source,
            entity_id=str(raw.get("user_id", "")),
            entity_type="user",
            action=str(raw.get("action", "login")),
            outcome=out,
            features={
                "login_rate_1m": _coerce_float(raw.get("login_rate_1m")),
                "distinct_geo_last_24h": _coerce_float(raw.get("distinct_geo_last_24h")),
                "failed_logins_1h": _coerce_float(raw.get("failed_logins_1h")),
                "impossible_travel_mins": _coerce_float(raw.get("impossible_travel_mins")),
                "new_device": _coerce_float(raw.get("new_device")),
                "new_geo": _coerce_float(raw.get("new_geo")),
                "hour_of_day": _coerce_float(raw.get("hour_of_day")),
            },
            tags=list(raw.get("tags", [])),
            raw=self._redact(raw),
        )


class EDRNormalizer(Normalizer):
    """端点行为：进程执行、横向移动、凭证窃取等特征。"""

    def __init__(self) -> None:
        super().__init__("edr")

    def normalize(self, raw: Dict[str, Any]) -> Event:
        return Event(
            event_id=raw.get("event_id", uuid.uuid4().hex),
            ts=float(raw.get("ts", time.time())),
            source=self.source,
            entity_id=str(raw.get("device_id", "")),
            entity_type="device",
            action=str(raw.get("action", "exec")),
            outcome=str(raw.get("outcome", "success")),
            features={
                "proc_launch_rate_1h": _coerce_float(raw.get("proc_launch_rate_1h")),
                "unique_child_procs_1h": _coerce_float(raw.get("unique_child_procs_1h")),
                "network_beacon_ms": _coerce_float(raw.get("network_beacon_ms")),
                "priv_escalation_flag": _coerce_float(raw.get("priv_escalation_flag")),
                "lateral_moves_1h": _coerce_float(raw.get("lateral_moves_1h")),
                "suspicious_cmdline": _coerce_float(raw.get("suspicious_cmdline")),
            },
            tags=list(raw.get("tags", [])),
            raw=self._redact(raw),
        )


_NORMALIZERS: Dict[str, Normalizer] = {
    "identity": IdentityNormalizer(),
    "edr": EDRNormalizer(),
}


class Ingestor:
    """Per-source ingestor: normalize then push into a backpressure buffer.

    每个 source 独立背压，隔离噪声源；缓冲满时按策略（阻塞/丢旧）优雅降级。
    无状态 —— 可跨节点水平扩展。
    """

    def __init__(self, buffer: BackpressureBuffer, normalizer: Optional[Normalizer] = None) -> None:
        self._buffer = buffer
        self._normalizer = normalizer
        self._accepted = 0
        self._rejected = 0
        self._errors = 0

    def ingest(self, raw: Dict[str, Any]) -> bool:
        """接入一条原始记录。返回是否进入缓冲。"""
        norm = self._normalizer
        if norm is None and raw.get("source") in _NORMALIZERS:
            norm = _NORMALIZERS[raw["source"]]
        if norm is None:
            self._errors += 1
            return False
        try:
            evt = norm.normalize(raw)
        except NormalizationError:
            self._errors += 1
            return False
        ok = self._buffer.put_nowait(evt)
        if ok:
            self._accepted += 1
        else:
            self._rejected += 1
        return ok

    def stats(self) -> Dict[str, int]:
        return {"accepted": self._accepted, "rejected": self._rejected, "errors": self._errors}
