# AegisFlow — 基础镜像（多阶段构建，最小化、无源码隐私暴露）
# 核心引擎零外部依赖，因此运行镜像非常轻量。
FROM python:3.13-slim AS runtime

# 非 root 运行（最小权限）
RUN groupadd -r aegisflow && useradd -r -g aegisflow aegisflow

WORKDIR /opt/aegisflow

# 仅拷贝应用代码与依赖声明（不拷贝 .env / key / 任何真实数据）
COPY src/ ./src/
COPY pyproject.toml requirements.txt README.md ./

# 安装为可执行包（无三方依赖，可选 extras 另行安装）
RUN pip install --no-cache-dir --no-deps -e .

# 运行时数据卷（审计链、事件缓存等）—— 生产挂持久化卷
RUN mkdir -p /data/audit && chown -R aegisflow:aegisflow /data

USER aegisflow

EXPOSE 8080 9090

# 默认进入 management plane API（env 可切换为 demo）
CMD ["aegisflow", "serve"]
