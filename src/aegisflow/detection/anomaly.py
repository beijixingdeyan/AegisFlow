"""Multi-dimensional anomaly scoring (检测引擎 · 异常评分层).

融合方法：将基线 z-score 的各特征异常合并为一个**多维异常分**，并保留每条
特征的贡献（为 SHAP 归因和可解释输出提供基础）。

评分：
  score = 加权归一化 z-score 峰值 + 特征数归一化
量化异常组合而非单点，减少误报（一个特征的偶然抖动不等于攻击）。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .baseline import EntityProfile


@dataclass
class AnomalyVerdict:
    entity_id: str
    score: float                        # 综合异常分 [0,1]
    above_threshold: bool
    zscores: Dict[str, float]           # 特征 z-score（仅已训练特征）
    contributions: Dict[str, float]     # 特征对总分的贡献（用于归因/解释）
    meaningful_features: List[str]      # 驱动异常的 top 特征

    def explain(self) -> Dict[str, object]:
        return {
            "entity_id": self.entity_id,
            "score": round(self.score, 4),
            "above_threshold": self.above_threshold,
            "top_features": self.meaningful_features,
            "contributions": {k: round(v, 4) for k, v in self.contributions.items()},
        }


def _sigmoid(x: float) -> float:
    # 数值稳定 sigmoid
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


class AnomalyScorer:
    """将基线 z-score 融合为 [0,1] 综合异常分。

    z-score 理论上无上界，我们用 sigmoid 映射到 [0,1] 并加权：
    score = 0.6 * sigmoid(max_abs_z - threshold)  +  0.4 * mean_active
    其中 mean_active 表示「超过 threshold 的异常特征占已训练特征的比例」。
    """

    def __init__(self, zscore_threshold: float = 3.5) -> None:
        self.zscore_threshold = zscore_threshold
        self.decision_threshold = 0.5   # 综合分是否「异常」的判定线（可配置）

    def evaluate(self, profile: EntityProfile, features: Dict[str, float]) -> AnomalyVerdict:
        zs = profile.zscore_features(features)
        valided_z = {k: v for k, v in zs.items() if v is not None}
        if not valided_z:
            return AnomalyVerdict(
                entity_id=profile.entity_id,
                score=0.0,
                above_threshold=False,
                zscores={},
                contributions={},
                meaningful_features=[],
            )
        # 归一化到 |z| 处理
        abs_zs = {k: abs(v) for k, v in valided_z.items()}
        max_z = max(abs_zs.values())
        active = [k for k, v in abs_zs.items() if v >= self.zscore_threshold]
        active_frac = len(active) / max(1, len(valided_z))

        # 融合分
        component_peak = _sigmoid(max_z - self.zscore_threshold)
        score = 0.6 * component_peak + 0.4 * active_frac
        score = max(0.0, min(1.0, score))

        # 特征贡献：按 |z| 归一化权重，用于 SHAP 风格归因
        tot = sum(abs_zs.values()) or 1.0
        contributions = {k: v / tot for k, v in abs_zs.items()}
        top = sorted(contributions, key=contributions.get, reverse=True)[:5]

        return AnomalyVerdict(
            entity_id=profile.entity_id,
            score=score,
            above_threshold=score >= self.decision_threshold,
            zscores=valided_z,
            contributions=contributions,
            meaningful_features=top,
        )
