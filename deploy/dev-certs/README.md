# 开发用 mTLS 证书目录（不在版本控制中）

此目录用于存放部署时生成的**开发/演示 mTLS 证书**。证书与私钥（`*.crt` / `*.key` / `*.pem` /
`*.p12` 等）已被 `.gitignore` 排除，**绝不提交到 GitHub**。

## 生成开发证书（示例，openssl）

```bash
# 1) 生成自签名 CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=AegisFlow Dev CA"

# 2) 生成本节点证书（同时作为服务端与客户端证书，用于双向 mTLS）
openssl req -newkey rsa:2048 -nodes \
  -keyout node.key -out node.csr \
  -subj "/CN=aegisflow-node"

openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 3) 在 .env 中配置：
#   AEGISFLOW_TLS_CERT_PATH=deploy/dev-certs/node.crt
#   AEGISFLOW_TLS_KEY_PATH=deploy/dev-certs/node.key
#   AEGISFLOW_TLS_CA_PATH=deploy/dev-certs/ca.crt
```

> 生产环境请使用内部 PKI 或外部 CA 签发，密钥存入 KMS/HSM。
> 本目录仅保留本 README，以便让 `.gitignore` 的 `!deploy/dev-certs/README.md` 例外生效。
