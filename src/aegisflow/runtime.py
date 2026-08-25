"""Runtime wiring: 把 Data Plane -> Detection -> Response 串成一条无状态工作流。

这个 worker 是可水平扩展(stateless)的执行单元：从 ResilientBus 拉批事件 ->
逐条过 DetectionPipeline -> 命中事件交 ResponseOrchestrator 决策 -> 审计。
多实例各自消费不同分区（见 docs/03-architecture.md），实现 >100k EPS。
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from .bus.resilient_queue import ResilientBus
from .config import AppConfig
from .dataplane.ingestion import Event
from .detection.pipeline import DetectionPipeline, DetectionResult
from .response.orchestrator import ResponseOrchestrator
from .security.access import PolicyEngine
from .security.audit import AuditChain

logger = logging.getLogger("aegisflow.runtime")


class Runtime:
    """组装好的可运行实例（供 CLI / API / 部署使用）。"""

    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.bus = ResilientBus(
            capacity=cfg.dataplane.buffer_size,
            high_watermark=cfg.dataplane.high_watermark,
            low_watermark=cfg.dataplane.low_watermark,
            batch_size=cfg.dataplane.batch_size,
        )
        self.pipeline = DetectionPipeline()
        self.audit = AuditChain(cfg.audit_dir)
        self.policy = PolicyEngine()
        self.response = ResponseOrchestrator(cfg.response, self.audit, self.policy)
        self._incidents: List[Dict[str, object]] = []
        self._events_consumed = 0

    def handle_batch(self, events: List[Event], subject: Optional[Dict[str, str]] = None) -> int:
        """处理一批事件，返回产生的事件(incident)数。"""
        subject = subject or {"identity": "pipeline", "role": "soc_lead"}
        incident_count = 0
        for evt in events:
            result = self.pipeline.process(evt)
            if result.is_incident:
                incident_count += 1
                self._record_incident(result, subject)
        return incident_count

    def ingest_raw(self, raw: Dict[str, object]) -> bool:
        """供外部调用的原始事件接入（Data Plane 入口）。"""
        from .dataplane.ingestion import Event
        evt = Event.from_dict(raw)
        return self.bus.publish(evt)

    def drain(self, max_events: Optional[int] = None) -> int:
        """消费并处理缓冲内事件，返回触发事件(incident)数。

        演示/单测用：把生产批次从 bus 取出交给 pipeline。生产环境由
        ResilientBus.process 或外部 worker 池驱动（同接口）。
        """
        produced = self.bus.snapshot().produced
        consumed = 0
        incident_count = 0
        while consumed < produced and (max_events is None or consumed < max_events):
            batch = self.bus._buffer.get_many(self.cfg.dataplane.batch_size, timeout_s=0.02)
            if not batch:
                # 让背压阻塞的 producer 有机会；多数场景已消费完
                break
            consumed += len(batch)
            incident_count += self.handle_batch(batch)
        self._events_consumed += consumed
        return incident_count

    def _record_incident(self, result: DetectionResult, subject: Dict[str, str]) -> None:
        record = result.to_dict()
        self._incidents.append(record)
        self.audit.record(
            subject.get("identity", "pipeline"),
            "detection:alert",
            f"{result.event.entity_type}:{result.event.entity_id}",
            "success",
            {"priority": result.priority, "final_score": result.final_score,
             "event_id": result.event.event_id},
        )
        logger.info("INCIDENT [%s] score=%.3f entity=%s :: %s",
                    result.priority, result.final_score, result.event.entity_id,
                    result.explanation.narrative)

    @property
    def incidents(self) -> List[Dict[str, object]]:
        return self._incidents

    def stats(self) -> Dict[str, object]:
        return {
            "bus": {
                "produced": self.bus.snapshot().produced,
                "consumed": self._events_consumed,
                "dropped": self.bus.snapshot().dropped,
                "buffer_size": self.bus.buffer_size,
            },
            "audit_chain_length": self.audit.length,
            "audit_chain_integrity": len(self.audit.verify()) == 0,
            "profiles": self.pipeline.profiler.count(),
            "incidents": len(self._incidents),
            "deployment": self.cfg.describe(),
        }
