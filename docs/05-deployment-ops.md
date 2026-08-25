# 05 · 部署、运维与三种模式

> 对应需求文档 Phase 2 第 7 节 与 硬性约束「部署模式 / 高可用 / 升级」。

---

## 1. 三种部署模式（架构不变，仅配置切换）

AegisFlow 的核心是**架构解耦**：同一份二进制，通过 `AEGISFLOW_MODE` 与若干配置选择
策略实现（传输、KMS、遥测、采集器），业务代码不因模式分支。

| 模式 | 私有化 on-premise | 混合云 hybrid | 纯 SaaS |
|------|------------------|---------------|---------|
| 控制/管理平面 | 客户机房，单租户 | 客户 VPC 内 | 厂商托管，多租户 |
| 数据平面 | 客户内部 | 客户 VPC + 云端遥测汇聚 | 厂商云 |
| KMS | 客户 Vault | 客户 Vault / 云端 KMS | 厂商 KMS（租户隔离） |
| 采集器 | 客户侧部署 | 客户侧 + 云侧 | Edge Agent / 云原生 |
| 配置 | `AEGISFLOW_MODE=onprem` | `=hybrid` | `=saas` |

- 配置入口：`config.py::AppConfig.from_env()`（`AEGISFLOW_MODE`、`AEGISFLOW_KMS_PROVIDER`、
  `AEGISFLOW_LLM_PROVIDER` 等），`/status` 会回显当前模式。

---

## 2. 一键部署

### 2.1 本地 / 私有化（Dev）
```bash
cp .env.example .env          # 填真实配置，.env 已 gitignore
export PYTHONPATH=src
python -m aegisflow demo      # 端到端演示
python -m aegisflow serve     # 管理平面 API
python run_tests.py           # 测试
```

### 2.2 Docker Compose（私有化单节点）
```bash
cd deploy && docker compose up -d
```
- 镜像多阶段构建、非 root 用户、仅拷贝 `src/`（不含任何 .env/key/真实数据）。
- 运行时数据（审计链等）挂持久卷 `aegisflow-data`。
- healthcheck 通过 `/health` 探活。

### 2.3 生产多活（Helm Chart / Terraform —— 部署蓝图）
```
多节点无状态核心（Active-Active） + 负载均衡 + 共识(etcd/Raft)做 leader 选举
+ 外部持久化事件总线（Kafka/NATS，按分区水平扩展）
+ 外部 KMS（Vault/AWS/阿里云） + 异地容灾存储（RPO<1min / RTO<5min）
+ mTLS 证书/CA 由内部 PKI 或外部 CA 签发
```
（本仓库不捆绑开箱的 Helm/Terraform 模板，以文档形式给出生产拓扑；`deploy/` 提供可运行的
Compose 最小集。）

---

## 3. 监控与告警（系统自身的可观测性）

- **健康探活**：`GET /health` —— 供负载均衡/编排器探活，返回 200 即存活。
- **运行状态**：`GET /status` —— 部署模式、KMS/LLM/响应模式、吞吐统计、审计链长度与完整性。
- **审计完整性自检**：`GET /audit/verify` —— 定期校验哈希链无篡改。
- **事件总线统计**：背压水位、丢弃数、熔断状态（`bus.snapshot()`）—— 用于容量与故障告警。

---

## 4. 升级策略（零停机滚动升级）

1. **无状态优先**：检测/采集 worker 无状态，先起新版本副本，通过 `/health` 后由负载均衡切换。
2. **策略/模型灰度**：检测策略与 AI 模型版本化，按实体/分区灰度，观察降噪/误报率后再全量。
3. **审计链兼容**：哈希链向前兼容（新节点追加，不重写旧块）。
4. **回滚**：保留上一版本镜像与数据快照，异常可快速回退。

---

## 5. 密钥与证书管理（运维安全）

- 生产必须使用外部 KMS（Vault/AWS/阿里云）；本地 KMS 仅演示/测试，绝不用于生产。
- mTLS 证书由内部 PKI 或外部 CA 签发，密钥存储于 KMS/HSM，业务进程不接触明文私钥。
- 证书轮换：MTLS 支持令牌刷新（`TokenManager`）与证书短期 TTL，降低泄露窗口。
