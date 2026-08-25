"""AegisFlow CLI.

用法：
  python -m aegisflow demo     运行端到端演示（合成流量 -> 检测 -> 响应 -> 审计）
  python -m aegisflow serve    启动管理平面 API（可选 mTLS）
  python -m aegisflow status   打印运行状态

所有命令以当前工作目录下的 .env / 环境变量 读取配置（见 config.py）。
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time

from .config import AppConfig, DeploymentMode
from .runtime import Runtime


def _synthetic_events(cluster: str = "user") -> list:
    """生成合成遥测，用于演示。纯本地、来源明确标注为 synthetic，绝不混入真实数据。"""
    seed = random.Random(7)
    events = []
    # 正常行为：登录频率低、无异常地理位置、失败登录少
    now = time.time()
    for i in range(400):
        events.append({
            "source": "identity", "entity_id": "alice", "entity_type": "user",
            "action": "login", "outcome": "success", "ts": now - i * 3,
            "features": {
                "login_rate_1m": seed.gauss(1.0, 0.3),
                "failed_logins_1h": max(0, seed.gauss(0.5, 0.2)),
                "impossible_travel_mins": 0.0,
                "new_device": 0.0, "new_geo": 0.0,
                "distinct_geo_last_24h": seed.gauss(2.0, 0.5),
                "hour_of_day": seed.gauss(10, 2),
            },
        })
        events.append({
            "source": "edr", "entity_id": "ws-112", "entity_type": "device",
            "action": "exec", "outcome": "success", "ts": now - i * 3,
            "features": {
                "proc_launch_rate_1h": seed.gauss(20, 4),
                "unique_child_procs_1h": seed.gauss(5, 1),
                "network_beacon_ms": 0.0, "priv_escalation_flag": 0.0,
                "lateral_moves_1h": 0.0, "suspicious_cmdline": 0.0,
            },
        })
    # 攻击注入：alice 撞库 + 不可能转移；ws-112 权限提升 + 可疑命令行（规则 critical）
    for k in range(30):
        events.append({
            "source": "identity", "entity_id": "alice", "entity_type": "user",
            "action": "login", "outcome": "failed", "ts": now - k * 2,
            "features": {
                "login_rate_1m": 12.0, "failed_logins_1h": 25.0,
                "impossible_travel_mins": 5.0, "new_device": 1.0, "new_geo": 1.0,
                "distinct_geo_last_24h": 9.0, "hour_of_day": 3.0,
            },
        })
    events.append({
        "source": "edr", "entity_id": "ws-112", "entity_type": "device",
        "action": "exec", "outcome": "success", "ts": now,
        "features": {
            "proc_launch_rate_1h": 9.0, "unique_child_procs_1h": 1.0,
            "network_beacon_ms": 120000.0, "priv_escalation_flag": 1.0,
            "lateral_moves_1h": 6.0, "suspicious_cmdline": 1.0,
        },
    })
    return events


def cmd_demo(cfg: AppConfig) -> int:
    rt = Runtime(cfg)
    rt.audit.record("system", "bootstrap", "demo-runtime", "success",
                    {"mode": cfg.mode.value})
    events = _synthetic_events()
    print(f"== AegisFlow demo | 部署模式={cfg.mode.value} | 注入 {len(events)} 个遥测事件 ==")

    start = time.perf_counter()
    for e in events:
        rt.ingest_raw(e)
    # 消费 batch（drain 内部拉批处理）
    rt.drain()
    consumed = rt.bus.snapshot().produced
    elapsed_ms = (time.perf_counter() - start) * 1000

    print(f"\n== 处理完成：{consumed} 事件，耗时 {elapsed_ms:.1f} ms "
          f"(≈{consumed / max(elapsed_ms / 1000, 1e-6):.0f} EPS/单线程)")
    print(f"== 触发事件（智能降噪后）：{len(rt.incidents)}\n")
    for inc in rt.incidents:
        print(json.dumps({
            "entity": inc["entity_id"],
            "priority": inc["priority"],
            "final_score": inc["final_score"],
            "explanation": inc["explanation"]["narrative"],
            "recommended": inc["reasoning"]["recommended_actions"],
        }, ensure_ascii=False, indent=2))
        print("-" * 60)

    # 响应编排演示（soc_lead 视角）
    print("== 响应编排（approve 模式：低危自动，其余人工）==")
    for inc in rt.incidents[:2]:
        from .detection.intelligence import Reasoning
        from .response.orchestrator import _canonical_action
        reasoning = Reasoning(
            summary=inc["explanation"]["narrative"],
            recommended_actions=inc["reasoning"]["recommended_actions"],
            confidence=inc["reasoning"]["confidence"],
            rationale=inc["reasoning"]["rationale"],
        )
        actions = rt.response.plan(inc["entity_id"], reasoning, inc["final_score"])
        subj = {"identity": "demo-lead", "role": "soc_lead"}
        for a in actions:
            rt.response.execute(a, subj)

    print("\n== 审计链校验 ==")
    problems = rt.audit.verify()
    print(f"完整性: {'OK（链完整）' if not problems else problems} | 记录数: {rt.audit.length}")
    print("\n== 运行统计 ==")
    print(json.dumps(rt.stats(), ensure_ascii=False, indent=2))
    return 0


def cmd_serve(cfg: AppConfig) -> int:
    from .api.server import serve
    rt = Runtime(cfg)
    server = serve(rt, cfg)
    scheme = "https(mTLS)" if cfg.tls.cert_path else "http"
    print(f"AegisFlow Management Plane listening on {scheme}://{cfg.api.host}:{cfg.api.port} "
          f"(mode={cfg.mode.value})")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aegisflow", description="AegisFlow CLI")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    sub.add_parser("serve")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    cfg = AppConfig.from_env()

    if args.cmd == "demo":
        return cmd_demo(cfg)
    if args.cmd == "serve":
        return cmd_serve(cfg)
    if args.cmd == "status":
        print(json.dumps(cfg.describe(), indent=2))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
