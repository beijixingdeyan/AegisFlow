# 安全说明（Security Policy）

## 受支持版本
- 当前 `main` 分支为开发/演示版，API 与行为可能变更。生产使用请基于已评审的发布标签。

## 报告漏洞
请**不要**在公开 issue 中披露潜在安全漏洞。建议通过私有渠道联系维护者，
并附上：影响范围、复现步骤、受影响版本、建议修复。

## 安全设计要点（详见 docs）
- 内部组件双向 mTLS，禁止隐式信任（`security/mtls.py`）。
- 传输 TLS 1.3；静态 AES-256-GCM + 外部 KMS（`security/crypto.py`）。
- 操作不可篡改哈希链审计（`security/audit.py`）。
- RBAC + ABAC 字段级访问控制（`security/access.py`）。
- 数据平面接入即 PII 脱敏；仓库 .gitignore 排除一切密钥/客户数据（上传 GitHub 前请复查）。

## 已知工程边界（生产前必须处理）
1. `crypto.py` 的认证加密构造为**教学/演示实现**，生产必须切换为标准 AES-256-GCM
   （OpenSSL / `cryptography`），接口不变。
2. `KMS_PROVIDER=local` 仅演示；生产必须使用外部 KMS（Vault / AWS KMS / 阿里云 KMS）。
3. `api/serve.py` 的 Bearer 令牌鉴权为**演示简化**，生产必须置于网关 / mTLS / 正式 IdP 之后。
4. 演示令牌（`demo-*-token`）仅供本地验证，禁止用于生产。
