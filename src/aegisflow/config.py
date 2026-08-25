"""Configuration & deployment-mode switching.

The same binary must run as:
  * on-premise  (私有化)  : all components colocated behind one edge
  * hybrid      (混合云)  : detection/response on customer VPC, telemetry in cloud
  * saas        (纯 SaaS) : multi-tenant managed service

We never branch inside the business logic on the mode string; instead mode
selects *strategies* (transport, KMS, telemetry sink, auth backend) that share a
common interface. Switching on-premise -> SaaS is therefore a config change,
not a code change.

No secrets live here: key material lives in the external KMS, referenced by id.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class DeploymentMode(str, Enum):
    ONPREM = "onprem"
    HYBRID = "hybrid"
    SAAS = "saas"


class KMSProvider(str, Enum):
    LOCAL = "local"      # demo/dev only — wraps a locally stored master key
    VAULT = "vault"      # HashiCorp Vault
    AWS = "aws"          # AWS KMS
    ALIYUN = "aliyun"    # Alibaba Cloud KMS


class LLMProvider(str, Enum):
    MOCK = "mock"        # offline heuristic scorer (no API key required)
    HTTP = "http"        # remote LLM endpoint (e.g. self-hosted or managed)


class ResponseMode(str, Enum):
    """Autonomy levels for the response orchestrator (渐进式自动化)."""
    OBSERVE = "observe"      # 只观察：产生告警，不动作
    SUGGEST = "suggest"      # 建议：生成动作建议，等待人工确认
    APPROVE = "approve"      # 半自动：低危可自动，高危需人工确认 (default)
    AUTO = "auto"            # 受信任全自动：仅审计圈定范围 (需合规评审)


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class KMSConfig:
    provider: KMSProvider = KMSProvider.LOCAL
    endpoint: str = ""
    data_key_ref: str = "aegisflow/master-data-key"
    # token/credentials are provided at runtime via the environment/secret store;
    # never serialized into config files.

    @classmethod
    def from_env(cls) -> "KMSConfig":
        provider = KMSProvider(_env("AEGISFLOW_KMS_PROVIDER", "local").lower())
        return cls(
            provider=provider,
            endpoint=_env("AEGISFLOW_KMS_ENDPOINT", ""),
            data_key_ref=_env("AEGISFLOW_DATA_KEY_REF", "aegisflow/master-data-key"),
        )


@dataclass(frozen=True)
class TLSConfig:
    cert_path: str = ""
    key_path: str = ""
    ca_path: str = ""
    require_client_cert: bool = True  # 双向 mTLS：强制客户端证书

    @classmethod
    def from_env(cls) -> "TLSConfig":
        return cls(
            cert_path=_env("AEGISFLOW_TLS_CERT_PATH", ""),
            key_path=_env("AEGISFLOW_TLS_KEY_PATH", ""),
            ca_path=_env("AEGISFLOW_TLS_CA_PATH", ""),
        )


@dataclass(frozen=True)
class DataPlaneConfig:
    ingest_port: int = 9090
    # 背压参数
    buffer_size: int = 100_000          # 内存缓冲条目上限
    high_watermark: float = 0.8         # 触发背压回压的缓冲水位
    low_watermark: float = 0.3          # 解除背压的水位
    drop_overflow: bool = False         # True=丢弃最老事件(优先保新), False=阻塞
    batch_size: int = 1024              # 每批处理的原始事件数
    collect_interval_s: float = 0.05    # 采集节拍 50ms

    @classmethod
    def from_env(cls) -> "DataPlaneConfig":
        return cls(
            ingest_port=int(_env("AEGISFLOW_INGEST_PORT", "9090")),
        )


@dataclass(frozen=True)
class DetectionConfig:
    # 特征/行为基线参数
    profile_window: int = 3600          # 基线滑动窗口（秒）
    zscore_threshold: float = 3.5        # 异常分数阈值（超出即候选异常）
    min_samples_per_entity: int = 30    # 建立基线的样本下限
    llm_provider: LLMProvider = LLMProvider.MOCK
    llm_endpoint: str = ""
    llm_api_key: str = ""
    # 可解释性 / 降噪
    top_features: int = 5               # SHAP 归因保留前 N 特征
    noise_priority_days: int = 1        # 降噪窗口

    @classmethod
    def from_env(cls) -> "DetectionConfig":
        return cls(
            llm_provider=LLMProvider(_env("AEGISFLOW_LLM_PROVIDER", "mock").lower()),
            llm_endpoint=_env("AEGISFLOW_LLM_ENDPOINT", ""),
            llm_api_key=_env("AEGISFLOW_LLM_API_KEY", ""),
        )


@dataclass(frozen=True)
class ResponseConfig:
    mode: ResponseMode = ResponseMode.APPROVE
    # 自动执行仅在受信任范围内
    auto_execute_low_risk: bool = True
    ack_timeout_s: int = 900            # 人工确认超时（秒）

    @classmethod
    def from_env(cls) -> "ResponseConfig":
        return cls(mode=ResponseMode(_env("AEGISFLOW_RESPONSE_MODE", "approve").lower()))


@dataclass(frozen=True)
class ApiConfig:
    host: str = "0.0.0.0"
    port: int = 8080

    @classmethod
    def from_env(cls) -> "ApiConfig":
        return cls(
            host=_env("AEGISFLOW_API_HOST", "0.0.0.0"),
            port=int(_env("AEGISFLOW_API_PORT", "8080")),
        )


@dataclass(frozen=True)
class AppConfig:
    mode: DeploymentMode = DeploymentMode.ONPREM
    log_level: str = "INFO"
    audit_dir: str = "data/audit"
    kms: KMSConfig = field(default_factory=KMSConfig.from_env)
    tls: TLSConfig = field(default_factory=TLSConfig.from_env)
    dataplane: DataPlaneConfig = field(default_factory=DataPlaneConfig.from_env)
    detection: DetectionConfig = field(default_factory=DetectionConfig.from_env)
    response: ResponseConfig = field(default_factory=ResponseConfig.from_env)
    api: ApiConfig = field(default_factory=ApiConfig.from_env)

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            mode=DeploymentMode(_env("AEGISFLOW_MODE", "onprem").lower()),
            log_level=_env("AEGISFLOW_LOG_LEVEL", "INFO").upper(),
            audit_dir=_env("AEGISFLOW_AUDIT_DIR", "data/audit"),
        )

    def describe(self) -> Dict[str, str]:
        """Human/machine readable mode descriptor for the /status endpoint."""
        return {
            "deployment_mode": self.mode.value,
            "kms_provider": self.kms.provider.value,
            "llm_provider": self.detection.llm_provider.value,
            "response_mode": self.response.mode.value,
            "mtls_required": str(self.tls.require_client_cert),
            "log_level": self.log_level,
        }
