"""
AegisFlow — AI-native Zero-Trust Behavioral Detection & Autonomous Response.

AegisFlow is a defensive security platform whose core value is a *hybrid
AI detection engine*: it learns per-entity behavior baselines, scores
multi-dimensional anomalies, applies deterministic guardrail rules, reasons
over the fused evidence with an LLM, and explains every decision (why/attribution)
before acting. It is designed to be privately deployable (on-premise), run as a
hybrid-cloud mesh, or be delivered as pure SaaS by changing configuration only.

Sub-packages
------------
- dataplane : high-throughput event ingestion with backpressure & normalization
- bus       : resilient HA event bus (bulkhead, circuit breaker, retry, replay)
- detection : hybrid AI detection pipeline (feature -> baseline -> anomaly -> reason)
- response  : autonomous response orchestration with human-in-the-loop tiers
- security  : zero-trust mTLS, tamper-proof hash-chain audit, field-level RBAC/ABAC,
              AES-256-GCM at-rest crypto with external KMS integration
- api       : Management-Plane REST API
"""

__version__ = "1.0.0"
__title__ = "AegisFlow"

# The Detection pipeline & Resilience primitives form the public surface most
# integrations touch.
__all__ = ["__version__", "__title__"]
