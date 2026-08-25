"""Hybrid AI detection engine sub-package."""

from .anomaly import AnomalyScorer, AnomalyVerdict
from .baseline import BaselineProfiler, EntityProfile, FeatureStat
from .explain import Explainer, Explanation
from .intelligence import (
    AbstractIntelligence,
    HttpIntelligence,
    MockIntelligence,
    Reasoning,
    build_intelligence,
)
from .pipeline import DetectionPipeline, DetectionResult
from .rules import Rule, RuleEngine

__all__ = [
    "AnomalyScorer",
    "AnomalyVerdict",
    "BaselineProfiler",
    "EntityProfile",
    "FeatureStat",
    "Explainer",
    "Explanation",
    "AbstractIntelligence",
    "HttpIntelligence",
    "MockIntelligence",
    "Reasoning",
    "build_intelligence",
    "DetectionPipeline",
    "DetectionResult",
    "Rule",
    "RuleEngine",
]
