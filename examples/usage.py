"""AegisFlow — 程序化使用示例（Data Plane -> Detection -> Response -> Audit）。

无需安装，直接运行：
    python examples/usage.py

演示如何以代码方式驱动核心引擎（而非仅用 CLI demo）。
"""

import os
import sys

# 确保能导入 src 下的包（从仓库任意位置运行时）
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from aegisflow.config import AppConfig
from aegisflow.runtime import Runtime


def main() -> None:
    os.environ.setdefault("AEGISFLOW_MODE", "onprem")
    os.environ.setdefault("AEGISFLOW_AUDIT_DIR", ".example-audit")

    rt = Runtime(AppConfig.from_env())

    # 1) 训练正常基线
    for i in range(50):
        rt.ingest_raw({
            "source": "identity", "entity_id": "dev-dave", "entity_type": "user",
            "action": "login", "outcome": "success",
            "features": {"failed_logins_1h": 0.2, "new_geo": 0.0,
                         "impossible_travel_mins": 0.0, "login_rate_1m": 1.0},
        })

    # 2) 注入攻击：撞库 + 新地域 + 不可能转移
    rt.ingest_raw({
        "source": "identity", "entity_id": "dev-dave", "entity_type": "user",
        "action": "login", "outcome": "failed",
        "features": {"failed_logins_1h": 35.0, "new_geo": 1.0,
                     "impossible_travel_mins": 7.0, "login_rate_1m": 15.0},
    })

    incidents = rt.drain()
    print(f"检测到事件数: {incidents}")
    for inc in rt.incidents:
        print(f"  [{inc['priority']}] {inc['entity_id']} score={inc['final_score']:.2f}")
        print(f"      解释: {inc['explanation']['narrative']}")
        print(f"      建议: {inc['reasoning']['recommended_actions']}")

    # 3) 校验审计链完整性
    ok = rt.audit.verify() == []
    print(f"\n审计链完整性: {'OK' if ok else rt.audit.verify()} (记录 {rt.audit.length} 条)")


if __name__ == "__main__":
    main()
