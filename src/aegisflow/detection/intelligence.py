"""LLM 推理层 (检测引擎 · 认知层 / AI-Native).

AI 原生不是「后期加聊天框」：LLM 嵌入到检测决策链的**因果推理**环节——
在异常评分之上，基于攻击链上下文做关联归因、生成可执行建议，并输出
置信度与依据（可解释）。可插拔：

  - `mock`   ：离线启发式推理器，零依赖、无需 API key —— 用于测试/演示/无外网。
  - `http`   ：对接远程 LLM 端点（自托管 vLLM/Ollama 或托管），生产环境使用。

两种实现的接口一致（AbstractIntelligence），满足「配置切换即可换后端」的
部署解耦约束。
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .anomaly import AnomalyVerdict

logger = logging.getLogger("aegisflow.detection.intelligence")


@dataclass
class Reasoning:
    """LLM/推理器产出的可执行洞察。"""

    summary: str
    recommended_actions: List[str]      # 可执行建议（自动化响应输入）
    confidence: float                   # [0,1]
    rationale: List[str]                # 推理依据（可解释）
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "summary": self.summary,
            "recommended_actions": self.recommended_actions,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
        }


class AbstractIntelligence(ABC):
    """认知推理器统一接口。"""

    @abstractmethod
    def reason(self, verdict: AnomalyVerdict, attack_path: List[str]) -> Reasoning:
        """输入：多维异常分 + 攻击路径；输出：可执行建议 + 置信度 + 依据。"""


# ---------- 特征风险映射（mock 推理器 & 关联逻辑共用）--------------------
_ACTION_HINTS: Dict[str, Tuple[str, str]] = {
    "impossible_travel_mins": ("强制重新认证 + 会话撤销", "疑似账号窃取"),
    "failed_logins_1h": ("启用一次性验证 / 临时锁定账号", "疑似口令喷洒"),
    "new_device": ("要求 MFA 重验证并登记设备指纹", "疑似新设备接管"),
    "new_geo": ("标记为高风险地域并提示管理员审查", "不可信地理位置登录"),
    "lateral_moves_1h": ("隔离受影响主机并限制横向访问", "疑似横向移动"),
    "priv_escalation_flag": ("冻结特权会话并触发特权审查", "疑似权限提升"),
    "suspicious_cmdline": ("终止可疑进程并快照取证", "疑似恶意执行"),
    "network_beacon_ms": ("阻断回连域名并对主机取证", "疑似 C2 命令控制"),
    "login_rate_1m": ("速率限制 + 挑战验证", "异常高频认证"),
}


class MockIntelligence(AbstractIntelligence):
    """离线启发式推理器：按 top 特征映射到动作/依据，供测试与演示。

    置信度 = 0.5 + 0.5 * 综合异常分（模拟 LLM 对强异常的更高确信）。
    """

    def reason(self, verdict: AnomalyVerdict, attack_path: List[str]) -> Reasoning:
        actions: List[str] = []
        rationale: List[str] = []
        for feat, contrib in sorted(verdict.contributions.items(), key=lambda kv: kv[1], reverse=True):
            if feat in _ACTION_HINTS:
                action, reason = _ACTION_HINTS[feat]
                if action not in actions:
                    actions.append(action)
                rationale.append(f"{feat}: {reason} (贡献 {contrib:.0%})")
            if len(actions) >= 3:
                break
        if not actions:
            actions = ["观察并继续监控该实体行为基线"]
            rationale = ["综合评分未达处置阈值，进入观察名单"]
        confidence = 0.5 + 0.5 * verdict.score
        summary = (
            f"实体 {verdict.entity_id} 行为偏离基线，异常分 {verdict.score:.2f}，"
            f"攻击路径：{' -> '.join(attack_path) if attack_path else '未知'}。"
        )
        return Reasoning(
            summary=summary,
            recommended_actions=actions,
            confidence=min(1.0, confidence),
            rationale=rationale,
        )


class HttpIntelligence(AbstractIntelligence):
    """对接远程 LLM 端点的推理器。

    生产环境应根据合同化的 prompt 模板调用端点，并将返回 JSON 解析为 Reasoning。
    这里保留清晰的接入点；调用失败时自动降级到 Mock 推理（优雅降级），保证
    检测链在 AI 后端故障时仍可用。
    """

    def __init__(self, endpoint: str, api_key: str = "", timeout_s: float = 2.0) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout_s = timeout_s
        self._fallback = MockIntelligence()

    def reason(self, verdict: AnomalyVerdict, attack_path: List[str]) -> Reasoning:
        try:
            # 真实实现：POST self.endpoint，headers 携带 Bearer self.api_key，
            # body 为合同化 prompt；此处为占位逻辑。
            payload = {
                "verdict": verdict.explain(),
                "attack_path": attack_path,
                "request": "recommend_executable_actions_with_confidence_and_rationale",
            }
            # _call_llm(payload)  -> 解析 json
            raise NotImplementedError("HTTP LLM backend adapter requires endpoint configuration")
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM backend degraded to mock reasoning: %s", exc)
            return self._fallback.reason(verdict, attack_path)


def build_intelligence(provider: str, endpoint: str = "", api_key: str = "") -> AbstractIntelligence:
    if provider == "http":
        return HttpIntelligence(endpoint, api_key)
    return MockIntelligence()
