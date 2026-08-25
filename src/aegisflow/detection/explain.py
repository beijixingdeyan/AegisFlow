"""AI 可解释性：SHAP 风格归因 + 攻击路径呈现 (检测引擎 · 可解释层).

安全分析师的信任来自「为什么」。本模块把 AnomalyScorer 的特征贡献转化为：
  - 归因列表（各特征对该告警的贡献，类似 SHAP value）
  - 一句话自然语言解释（分析友好）
  - 关联攻击路径（ATT&CK 战术阶段链）
这满足「每个 AI 决策必须能解释为什么」的约束，也支撑「默认安全、透明开放」—— 
所有检测逻辑与原因为分析师可审计。

说明：这里不依赖重型的 shap 库以保证免安装可运行；生产可替换为真实 SHAP/
LIME 后端（见 docs/04-ai-interpretability.md），接口不变。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .anomaly import AnomalyVerdict


@dataclass
class Explanation:
    verdict: AnomalyVerdict
    narrative: str = ""
    attributed_features: List[Dict[str, object]] = field(default_factory=list)
    attack_path: List[str] = field(default_factory=list)   # ATT&CK 战术链

    def to_dict(self) -> Dict[str, object]:
        return {
            "narrative": self.narrative,
            "attributed_features": self.attributed_features,
            "attack_path": self.attack_path,
            "score": round(self.verdict.score, 4),
        }


# 特征 -> (中文标签, ATT&CK 战术阶段)
_FEATURE_META: Dict[str, tuple] = {
    "failed_logins_1h": ("失败登录数(1h)", "TA0006 Credential Access"),
    "impossible_travel_mins": ("地理不可能转移(分钟)", "TA0001 Initial Access"),
    "new_geo": ("新地理位置", "TA0001 Initial Access"),
    "new_device": ("新设备", "TA0001 Initial Access"),
    "distinct_geo_last_24h": ("24h 不同位置数", "TA0001 Initial Access"),
    "login_rate_1m": ("登录频率(1m)", "TA0006 Credential Access"),
    "hour_of_day": ("登录时段", "TA0001 Initial Access"),
    "lateral_moves_1h": ("横向移动(1h)", "TA0008 Lateral Movement"),
    "priv_escalation_flag": ("权限提升标志", "TA0004 Privilege Escalation"),
    "suspicious_cmdline": ("可疑命令行", "TA0002 Execution"),
    "network_beacon_ms": ("C2 回连间隔(ms)", "TA0011 Command & Control"),
    "unique_child_procs_1h": ("子进程多样性(1h)", "TA0002 Execution"),
    "proc_launch_rate_1h": ("进程启动频率(1h)", "TA0002 Execution"),
}


class Explainer:
    """把 AnomalyVerdict 转成分析师可读、可审计的解释。"""

    def explain(self, verdict: AnomalyVerdict) -> Explanation:
        contribs = sorted(verdict.contributions.items(), key=lambda kv: kv[1], reverse=True)
        attributed = [
            {
                "feature": k,
                "contribution": round(v, 4),
                "label": _FEATURE_META.get(k, (k, "Unknown"))[0],
                "tactics": _FEATURE_META.get(k, (k, "Unknown"))[1],
                "zscore": round(verdict.zscores.get(k, 0.0), 2),
            }
            for k, v in contribs[:5]
        ]
        path: List[str] = []
        for item in attributed:
            t = item["tactics"].split(" ", 1)[0]
            if t not in path:
                path.append(t)

        narrative = self._narrate(verdict, attributed)
        return Explanation(
            verdict=verdict,
            narrative=narrative,
            attributed_features=attributed,
            attack_path=path,
        )

    @staticmethod
    def _narrate(verdict: AnomalyVerdict, attr: List[Dict[str, object]]) -> str:
        if not attr:
            return f"实体 {verdict.entity_id} 行为正常，异常分 {verdict.score:.2f}。"
        top = attr[0]
        features_cn = "、".join(str(a["label"]) for a in attr[:3])
        return (
            f"实体 {verdict.entity_id} 出现行为偏离基线：异常分 {verdict.score:.2f}，"
            f"主要归因于「{features_cn}」，其中「{top['label']}」贡献最大 "
            f"({float(top['contribution']):.0%})，对应战术阶段 {top['tactics']}。"
        )
