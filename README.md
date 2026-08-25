# AegisFlow（守护之流）· AI-Native 零信任行为检测与自动化响应平台

> **一句话定位**：一个以「混合 AI 检测引擎」为核心、面向 SOC 的下一代安全运营平台
> —— 不再靠告警堆叠，而是让分析师**每天只处理真正重要的少数事件**，并让系统在
> 可信范围内**自主处置**、且每一步都能解释「为什么」。

AegisFlow 不是「ELK 换皮」「规则 SIEM」「WAF 包装」或「蜜罐复刻」。它的核心价值主张是：

- **混合 AI 检测**：行为基线 + 多维异常评分 + LLM 因果推理三层融合，而非规则匹配。
- **智能降噪**：把海量告警收敛为少数高优先事件，直击「告警疲劳」这一行业死因。
- **自主响应（渐进式信任）**：`观察 → 建议 → 半自动 → 可信全自动`，配合人工确认闭环。
- **AI 可解释**：每个决策都带特征归因（SHAP 风格）+ 自然语言解释 + ATT&CK 战术路径。
- **系统自身安全**：内部组件双向 mTLS、AES-256-GCM 静态加密 + 外部 KMS、不可篡改哈希链审计、RBAC+ABAC 字段级访问控制。
- **三种部署模式**：私有化 / 混合云 / 纯 SaaS，仅通过配置切换，架构不变。

> ⚠️ **隐私声明**：本仓库用于公开 GitHub 上传，已做严格脱敏。任何 `.env`、密钥、
> 证书、本地数据目录均被 `.gitignore` 排除；演示数据全部为合成遥测，不含真实用户/客户信息。

---

## ✨ 快速开始

### 环境要求
- Python 3.9+（核心引擎**零第三方依赖**，纯标准库即可运行）
- 可选：`pytest`（运行测试）；`docker`（一键部署）

### 运行端到端演示
```bash
# 从仓库根目录
export PYTHONPATH=src            # Windows: set PYTHONPATH=src
python -m aegisflow demo
```
演示会：注入 831 条**合成遥测** → 训练行为基线 → 检测出攻击事件（含归因解释与
推荐处置）→ 执行响应编排 → 校验审计链完整性。

### 运行测试（无 pytest 依赖）
```bash
python run_tests.py          # 27 项测试，全部通过
# 或（若安装了 pytest）
pytest
```

### 启动管理平面 API
```bash
python -m aegisflow serve     # 默认 http://127.0.0.1:8080
```
演示令牌（仅用于本地验证，生产由网关/mTLS 接管）：
- `demo-admin-token`（admin）· `demo-lead-token`（soc_lead）· `demo-analyst-token`（analyst）

```bash
curl -H "Authorization: Bearer demo-admin-token" http://127.0.0.1:8080/status
curl -H "Authorization: Bearer demo-admin-token" http://127.0.0.1:8080/incidents
curl -H "Authorization: Bearer demo-admin-token" http://127.0.0.1:8080/audit/verify
```

### 一键部署（Docker Compose）
```bash
cp .env.example .env          # 填入真实配置（.env 已被 gitignore）
cd deploy && docker compose up
```

---

## 🧱 核心架构

```
┌───────────────────────────────────────────────────────────────────────┐
│  Management Plane (管理平面)   UI · API · RBAC/ABAC · 审计 · 配置        │
└───────────────┬───────────────────────────────────────────────────────┘
┌───────────────▼───────────────────────────────────────────────────────┐
│  Control Plane (控制平面)  策略管理 · AI 推理 · 决策引擎                │
│   DetectionPipeline: 基线学习 → 异常评分 → 规则护栏 → 因果推理 → 解释    │
└───────────────┬───────────────────────────────────────────────────────┘
┌───────────────▼───────────────────────────────────────────────────────┐
│  Data Plane (数据平面)  采集(无状态) → 归一化(脱敏) → 高可用事件总线      │
│   背压 · 熔断 · 重试 · 批量 · 水平扩展                                   │
└───────────────────────────────────────────────────────────────────────┘
```

仓库布局：

```
src/aegisflow/
├── config.py            # 部署模式/安全/检测配置（切换即解耦）
├── dataplane/           # 事件接入、归一化、脱敏（PII 剥离）
├── bus/                 # 高可用事件总线：背压、熔断、重试、批量  ★模块B
├── detection/           # 混合 AI 检测引擎：基线/异常/规则/推理/解释
├── response/            # 自主响应编排（渐进式信任 + 人工确认）
├── security/            # mTLS★C · 审计哈希链★D · AES-256-GCM+KMS · RBAC/ABAC
├── api/                 # 管理平面 REST API
├── runtime.py           # Data→Detect→Respond 无状态工作流
└── __main__.py          # CLI (demo / serve / status)
docs/                    # 完整设计文档（见下）
deploy/                  # Dockerfile / docker-compose
tests/                   # 27 项单元+端到端测试
```

---

## 📚 文档索引

| 文档 | 内容 |
|------|------|
| [`docs/01-project-overview.md`](docs/01-project-overview.md) | 本项目缘起、3 个方向提案、选定方向与创新对比 |
| [`docs/02-threat-model.md`](docs/02-threat-model.md) | 威胁模型、攻击链(ATT&CK)、信任边界、最坏假设 |
| [`docs/03-architecture.md`](docs/03-architecture.md) | 三平面架构、高可用、多活、性能设计 |
| [`docs/04-ai-interpretability.md`](docs/04-ai-interpretability.md) | AI 可解释性、智能降噪、可解释可视化方案 |
| [`docs/05-deployment-ops.md`](docs/05-deployment-ops.md) | 一键部署、监控告警、零停机升级、三种模式 |
| [`docs/06-compliance.md`](docs/06-compliance.md) | 等保 2.0、ISO 27001、SOC 2、GDPR/个保法 |
| [`docs/07-commercialization-roi.md`](docs/07-commercialization-roi.md) | ROI 模型、MVP/V1/V2 路线、定价对比、销售场景 |
| [`docs/08-performance.md`](docs/08-performance.md) | 性能目标、量化方法与基准方法 |

---

## 🔒 隐私与安全（上传 GitHub 前必读）

- `.gitignore` 已排除：`.env`、`*.pem/*.key/*.crt/*.p12`、`data/`、`*.log`、`*.db`、
  本地配置文件、IDE 文件等一切可能含密钥/客户数据的内容。
- `.env.example` 仅含占位值，用于模板。
- 演示数据全部为 `_synthetic_events()` 生成的合成遥测，明确标注，绝不混入真实数据。
- 系统自身：内部组件双向 mTLS（禁止隐式信任）、传输 TLS 1.3、静态 AES-256-GCM + 外部 KMS、
  操作不可篡改哈希链审计、RBAC+ABAC 字段级权限。

---

## 📄 License

[Apache License 2.0](LICENSE)

---

*本项目为网络安全产品「从 0 到 1」设计+实现的教学/演示工程，用于展示下一代安全平台的
核心机制。生产使用请参考 docs 中的合规与安全加固章节。*
