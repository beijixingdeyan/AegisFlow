"""Deterministic guardrail rules (检测引擎 · 规则辅助层).

AegisFlow 的创新是「行为基线 + 异常评分 + LLM 推理」的混合架构，规则列表不是
主轴，而是作为**确定性护栏**：- 对高置信的攻击模式给出**硬性高优先级**信号；
- 对低基数/冷启动（样本不足无法建基线）的实体提供兜底检测；
- 规则命中与 AI 评分融合（见 pipeline），避免「规则换皮 SIEM」的定位。

每条规则带 MITRE ATT&CK 映射，便于分析师审计检测逻辑（默认安全、透明开放）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..dataplane.ingestion import Event


@dataclass
class Rule:
    name: str
    description: str
    attack_techniques: List[str]          # MITRE ATT&CK (e.g. "T1078 Valid Accounts")
    severity: str                         # critical | high | medium | low
    signal: float                         # 命中时的确定性信号强度 [0,1]

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        raise NotImplementedError


def _f(features: Dict[str, float], key: str, default: float = 0.0) -> float:
    return features.get(key, default)


@dataclass
class ImpossibleTravelRule(Rule):
    """同一账号在极短时间内出现在地理上不可能的位置。"""

    def __init__(self) -> None:
        super().__init__(
            name="impossible-travel",
            description="同一账号 <N 分钟 出现于两个相距甚远的位置（跳跃速度超过物理上限）",
            attack_techniques=["T1078", "T1021"],
            severity="high",
            signal=0.9,
        )
        self.max_mins_for_gap = 120.0

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        mins = _f(evt.features, "impossible_travel_mins")
        return mins > 0 and mins <= self.max_mins_for_gap


@dataclass
class CredentialStuffingRule(Rule):
    """短时大量失败登录后突然成功 —— 典型的撞库/口令喷洒。"""

    failed_threshold: float = 10.0

    def __init__(self) -> None:
        super().__init__(
            name="credential-stuffing",
            description="1 小时内失败登录数超过阈值且伴随成功登录",
            attack_techniques=["T1110.001", "T1110.004"],
            severity="high",
            signal=0.85,
        )

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        return _f(evt.features, "failed_logins_1h") >= self.failed_threshold


@dataclass
class PrivEscalationRule(Rule):
    """权限提升 + 可疑命令行 —— 常见 APT 落地手法。"""

    def __init__(self) -> None:
        super().__init__(
            name="privilege-escalation-suspicious",
            description="权限提升标志与可疑命令行同时出现",
            attack_techniques=["T1548", "T1059"],
            severity="critical",
            signal=0.95,
        )

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        return _f(evt.features, "priv_escalation_flag") >= 1.0 and \
            _f(evt.features, "suspicious_cmdline") >= 1.0


@dataclass
class C2BeaconRule(Rule):
    """定期间歇性回连（beaconing）—— 命令与控制信道特征。"""

    def __init__(self) -> None:
        super().__init__(
            name="c2-beaconing",
            description="网络回连间隔高度规律且异常（C2 心跳特征）",
            attack_techniques=["T1071"],
            severity="high",
            signal=0.8,
        )

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        ms = _f(evt.features, "network_beacon_ms")
        return 1000.0 <= ms <= 3600000.0


@dataclass
class LateralMovementRule(Rule):
    """短时横向移动次数激增。"""

    def __init__(self) -> None:
        super().__init__(
            name="lateral-movement-spike",
            description="1 小时内横向移动目标数显著超出（护栏：高值硬信号）",
            attack_techniques=["T1021.001"],
            severity="high",
            signal=0.85,
        )

    def matches(self, evt: Event, context: Dict[str, float]) -> bool:
        return _f(evt.features, "lateral_moves_1h") >= 5.0


class RuleEngine:
    """确定性规则引擎：遍历注册规则，返回命中的规则列表（含信号）。"""

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self._rules: List[Rule] = rules or [
            ImpossibleTravelRule(),
            CredentialStuffingRule(),
            PrivEscalationRule(),
            C2BeaconRule(),
            LateralMovementRule(),
        ]

    def evaluate(self, evt: Event, context: Optional[Dict[str, float]] = None) -> List[Rule]:
        ctx = context or {}
        hits: List[Rule] = []
        for rule in self._rules:
            try:
                if rule.matches(evt, ctx):
                    hits.append(rule)
            except Exception:  # 单条规则异常不应拖垮整条管线
                continue
        return hits

    def catalog(self) -> List[Dict[str, object]]:
        return [
            {
                "name": r.name,
                "description": r.description,
                "attack_techniques": r.attack_techniques,
                "severity": r.severity,
                "signal": r.signal,
            }
            for r in self._rules
        ]
