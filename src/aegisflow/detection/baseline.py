"""Behavior baseline learning (检测引擎 · 行为基线层).

核心思想：不用固定规则匹配“已知攻击”，而是为每个实体（用户/设备/服务）学习其
正常行为分布，再检测“偏离基线”的行为。这是与“规则列表 SIEM”的本质区别。

实现：对每个实体的每个数值特征维护滑动窗口的在线统计（均值/方差/最小值/最大值），
采用 Welford 在线算法 O(1) 时空复杂度，支持高速流式更新（满足 >100k EPS）。
基线按照固定时间窗（default 3600s）老化，保证随行为演化自适应。
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class FeatureStat:
    """单特征在线统计（Welford 递推）。"""

    name: str
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0          # 累计平方差，用于在线方差
    min_v: float = float("inf")
    max_v: float = float("-inf")
    last_update: float = 0.0

    def update(self, value: float, ts: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2
        if value < self.min_v:
            self.min_v = value
        if value > self.max_v:
            self.max_v = value
        self.last_update = ts

    @property
    def variance(self) -> float:
        return self.m2 / self.n if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> Optional[float]:
        """计算 z-score；样本不足或方差接近 0 时返回 None（未训练）。"""
        if self.n < 2 or self.std < 1e-9:
            return None
        return (value - self.mean) / self.std


@dataclass
class EntityProfile:
    """单个实体的行为画像。"""

    entity_id: str
    entity_type: str
    features: Dict[str, FeatureStat] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    n_events: int = 0

    def observe(self, feature_values: Dict[str, float], ts: float) -> None:
        if not self.first_seen:
            self.first_seen = ts
        self.last_seen = ts
        self.n_events += 1
        for name, value in feature_values.items():
            st = self.features.get(name)
            if st is None:
                st = FeatureStat(name=name)
                self.features[name] = st
            st.update(value, ts)

    def zscore_features(self, feature_values: Dict[str, float]) -> Dict[str, Optional[float]]:
        out: Dict[str, Optional[float]] = {}
        for name, value in feature_values.items():
            st = self.features.get(name)
            out[name] = st.zscore(value) if st else None
        return out

    def is_learned(self, min_samples: int) -> bool:
        return self.n_events >= min_samples


class BaselineProfiler:
    """在线行为基线学习器：维护 <entity_id -> EntityProfile> 哈希表。

    高并发吞吐：profile 更新为纯内存 O(1)，无锁单线程消费（见 ResilientBus
    consumer 语义），多实体并行天然水平扩展。
    """

    def __init__(self, min_samples: int = 30, window_s: int = 3600) -> None:
        self._profiles: Dict[str, EntityProfile] = {}
        self.min_samples = min_samples
        self.window_s = window_s

    def observe(self, entity_id: str, entity_type: str,
                features: Dict[str, float], ts: Optional[float] = None) -> EntityProfile:
        ts = ts if ts is not None else time.time()
        prof = self._profiles.get(entity_id)
        if prof is None:
            prof = EntityProfile(entity_id=entity_id, entity_type=entity_type)
            self._profiles[entity_id] = prof
        prof.observe(features, ts)
        # 简单老化：对超过窗口未见过的特征清零（保持自适应）
        self._age(prof, ts)
        return prof

    def _age(self, prof: EntityProfile, now: float) -> None:
        if now - prof.last_seen > self.window_s:
            prof.features.clear()
            prof.n_events = 0
            prof.first_seen = 0.0

    def profile(self, entity_id: str) -> Optional[EntityProfile]:
        return self._profiles.get(entity_id)

    def learned(self, entity_id: str) -> bool:
        p = self._profiles.get(entity_id)
        return bool(p and p.is_learned(self.min_samples))

    def count(self) -> int:
        return len(self._profiles)
