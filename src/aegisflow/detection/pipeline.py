"""Hybrid AI detection pipeline (检测引擎 · 编排层).

数据流：
  Event ──> baseline.observe ──> anomaly.evaluate ──> rules.evaluate ──> intelligence.reason
                     │                            │                        │
                     └───── 行为基线(在线) ────────┴── 规则护栏(确定性) ─────┴── LLM 因果推理

融合策略（Rule + AI 混合）：
  final = max(w_ai * anomaly.score, w_rule * rule_signal)
  规则提供确定性强信号（护栏），AI 提供对新颖/未知威胁的泛化能力；
  两者任一超过阈值即告警，但告警必须带有可解释输出（归因 + 推理）与智能降噪分级。

本管线被 detection worker（见 module_demo / api worker）以无状态方式调用，
便于水平扩展（>100k EPS），端到端延迟 <50ms（纯内存、无外部 IO）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..dataplane.ingestion import Event
from .anomaly import AnomalyScorer, AnomalyVerdict
from .baseline import BaselineProfiler, EntityProfile
from .explain import Explainer, Explanation
from .intelligence import AbstractIntelligence, Reasoning, build_intelligence
from .rules import Rule, RuleEngine


@dataclass
class DetectionResult:
    event: Event
    verdict: AnomalyVerdict
    explanation: Explanation
    reasoning: Reasoning
    rule_hits: List[Rule]
    final_score: float
    is_incident: bool            # 是否形成需处置的“事件”（智能降噪后）
    priority: str               # critical | high | medium | low | none
    entity_learned: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "event_id": self.event.event_id,
            "entity_id": self.event.entity_id,
            "entity_type": self.event.entity_type,
            "action": self.event.action,
            "anomaly": self.verdict.explain(),
            "explanation": self.explanation.to_dict(),
            "reasoning": self.reasoning.to_dict(),
            "rule_hits": [r.name for r in self.rule_hits],
            "final_score": round(self.final_score, 4),
            "is_incident": self.is_incident,
            "priority": self.priority,
            "entity_learned": self.entity_learned,
        }


class DetectionPipeline:
    """无状态编排：注入各子组件，逐事件产出可解释检测结果。"""

    def __init__(
        self,
        profiler: Optional[BaselineProfiler] = None,
        scorer: Optional[AnomalyScorer] = None,
        rules: Optional[RuleEngine] = None,
        intelligence: Optional[AbstractIntelligence] = None,
        explainer: Optional[Explainer] = None,
        ai_weight: float = 0.55,
        rule_weight: float = 0.95,
        incident_threshold: float = 0.42,
    ) -> None:
        self.profiler = profiler or BaselineProfiler()
        self.scorer = scorer or AnomalyScorer()
        self.rules = rules or RuleEngine()
        self.intelligence = intelligence or build_intelligence("mock")
        self.explainer = explainer or Explainer()
        self.ai_weight = ai_weight
        self.rule_weight = rule_weight
        self.incident_threshold = incident_threshold

    def process(self, evt: Event) -> DetectionResult:
        # 1) 行为基线学习
        prof = self.profiler.observe(evt.entity_id, evt.entity_type, evt.features, evt.ts)
        learned = prof.is_learned(self.profiler.min_samples)

        # 2) 多维异常评分
        verdict = self.scorer.evaluate(prof, evt.features)

        # 3) 确定性规则护栏
        rule_hits = self.rules.evaluate(evt)
        max_rule_signal = max((r.signal for r in rule_hits), default=0.0)

        # 4) 融合
        final_score = max(self.ai_weight * verdict.score, self.rule_weight * max_rule_signal)

        # 5) 可解释 + LLM 推理
        explanation = self.explainer.explain(verdict)
        reasoning = self.intelligence.reason(verdict, explanation.attack_path)

        # 6) 智能降噪 + 分级
        is_incident = final_score >= self.incident_threshold
        priority = _prioritize(is_incident, learned, verdict.score, max_rule_signal)

        return DetectionResult(
            event=evt,
            verdict=verdict,
            explanation=explanation,
            reasoning=reasoning,
            rule_hits=rule_hits,
            final_score=final_score,
            is_incident=is_incident,
            priority=priority,
            entity_learned=learned,
        )


def _prioritize(is_incident: bool, learned: bool, ai_score: float, rule_signal: float) -> str:
    """给事件分级：仅对「真正值得分析师看」的产出 high/critical，实现智能降噪。"""
    if not is_incident:
        return "none"
    if rule_signal >= 0.9:
        return "critical"
    if ai_score >= 0.7 or rule_signal >= 0.8:
        return "high"
    if not learned:
        # 冷启动期的伪异常降级，避免噪音
        return "low"
    return "medium"
