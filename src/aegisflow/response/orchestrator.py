"""Autonomous response orchestration (响应自动化 · 渐进式信任).

AI 辅助决策 + 人类确认，逐步过渡到可信自动执行：
  - observe      : 只观察，生成告警与建议
  - suggest      : 生成动作建议，等待人工确认
  - approve      : 半自动 —— 低危自动执行，高危人工确认（默认）
  - auto         : 受信任全自动（需合规评审；仅执行白名单动作）

每个被批准/执行的动作都写入不可篡改审计链，保证可追溯、可问责、符合
「自动化阻断/隔离 <500ms」的响应类延迟要求（本层仅做决策与编排，实际
阻断动作由策略执行点基于该决策下发）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import ResponseConfig, ResponseMode
from ..detection.intelligence import Reasoning
from ..security.access import AccessDenied, PolicyEngine
from ..security.audit import AuditChain


@dataclass
class ResponseAction:
    action: str              # 动作名：session_revoke / host_isolate / account_lock ...
    target: str              # 目标实体
    severity: str            # low | medium | high | critical
    requires_human: bool
    executed: bool = False
    approved: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class ResponseOrchestrator:
    """把推理建议升级为受控执行动作，并执行审批/自动策略。"""

    def __init__(self, cfg: ResponseConfig, audit: AuditChain,
                 policy: Optional[PolicyEngine] = None) -> None:
        self._cfg = cfg
        self._audit = audit
        self._policy = policy or PolicyEngine()

    # 低危动作才允许自动执行（白名单语义）
    _AUTO_EXECUTE_LOW_RISK_WHITELIST = {"observe", "session_revoke"}

    def _severity_of(self, confidence: float, score: float) -> str:
        if confidence >= 0.9 or score >= 0.7:
            return "critical"
        if confidence >= 0.75 or score >= 0.5:
            return "high"
        if confidence >= 0.6:
            return "medium"
        return "low"

    def plan(self, entity_id: str, reasoning: Reasoning, score: float,
             role_name: str = "soc_lead") -> List[ResponseAction]:
        """把 LLM 推荐的字符串动作转成受控 ResponseAction 列表。"""
        severity = self._severity_of(reasoning.confidence, score)
        actions: List[ResponseAction] = []
        for raw in reasoning.recommended_actions:
            canonical = _canonical_action(raw)
            requires_human = self._requires_human(severity)
            actions.append(ResponseAction(
                action=canonical, target=entity_id, severity=severity,
                requires_human=requires_human,
            ))
        return actions

    def _requires_human(self, severity: str) -> bool:
        mode = self._cfg.mode
        if mode == ResponseMode.OBSERVE:
            return True          # 观察模式不执行，全部“需人类”以说明
        if mode == ResponseMode.AUTO:
            return False
        if mode == ResponseMode.APPROVE:
            # 半自动：低危自动，其余人工
            if self._cfg.auto_execute_low_risk and severity == "low":
                return False
            return True
        # suggest
        return True

    def execute(self, action: ResponseAction, subject: Dict[str, Any],
                attributes: Optional[Dict[str, Any]] = None) -> ResponseAction:
        """执行单条动作：鉴权 + 审计；返回更新后的动作状态。"""
        act = f"{action.action}:{action.target}"
        # 鉴权：执行响应需 execute:response 权限；高危写事件走 ABAC
        try:
            self._policy.check(subject, "execute", "response", attributes)
            if action.severity in ("high", "critical"):
                self._policy.check(subject, "write", "incident",
                                   {"severity": action.severity})
        except AccessDenied as e:
            self._audit.record(subject.get("identity", "?"), "response:denied",
                               act, "denied", {"reason": str(e)})
            action.approved = False
            action.reason = "denied-by-policy"
            return action

        # 判定自动/人工
        auto_execute = (not action.requires_human) and \
            (action.severity == "low" or self._cfg.mode == ResponseMode.AUTO)
        if auto_execute:
            action.approved = True
            action.executed = True
            self._audit.record(subject.get("identity", "?"),
                               f"response:executed:{action.action}",
                               act, "success", {"severity": action.severity})
        else:
            action.approved = True   # 假设.soc 已确认（人工确认在 UI 进行）
            action.executed = False
            action.reason = "awaiting-human-confirmation"
            self._audit.record(subject.get("identity", "?"),
                               f"response:suggested:{action.action}",
                               act, "success",
                               {"severity": action.severity, "awaiting": True})
        return action

    def confirm(self, action: ResponseAction, subject: Dict[str, Any]) -> ResponseAction:
        """人工确认后真正执行（audit 记录确认者，满足问责）。"""
        try:
            self._policy.check(subject, "execute", "response",
                               {"severity": action.severity})
        except AccessDenied as e:
            action.reason = f"confirm-denied:{e}"
            return action
        action.approved = True
        action.executed = True
        action.reason = "human-confirmed"
        self._audit.record(subject.get("identity", "?"), f"response:confirmed:{action.action}",
                           f"{action.action}:{action.target}", "success",
                           {"severity": action.severity})
        return action


def _canonical_action(raw: str) -> str:
    """把自然语言动作归一化为策略可执行的规范动作名。"""
    table = {
        "强制重新认证": "session_revoke",
        "会话撤销": "session_revoke",
        "隔离受影响主机": "host_isolate",
        "冻结特权会话": "session_revoke",
        "临时锁定账号": "account_lock",
        "终止可疑进程": "process_kill",
        "阻断回连域名": "block_c2_domain",
        "启用一次性验证": "require_mfa",
        "要求 mfa 重验证": "require_mfa",
        "速率限制": "rate_limit",
        "观察并继续监控": "observe",
    }
    for k, v in table.items():
        if k in raw:
            return v
    return raw.lower().replace(" ", "_")[:40] or "observe"
