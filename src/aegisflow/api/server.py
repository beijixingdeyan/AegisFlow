"""Management-Plane REST API (管理平面 · 纯 stdlib 实现).

提供管理/查询能力：
  GET  /status                运行状态与部署模式
  GET  /health                健康检查（用于 HA 探活）
  POST /events                接入原始事件 (Data Plane 入口)
  GET  /incidents             查询事件（RBAC+字段脱敏）
  GET  /policies              RBAC/ABAC 策略快照（透明开放、可审计）
  GET  /rules                 检测规则编目（透明开放：客户可审计检测逻辑）
  GET  /audit/verify          审计链完整性校验
  GET  /audit/recent          最近审计记录

安全：真实部署下此接口应置于 mTLS / 反向代理之后；这里做最小内置鉴权演示
（Bearer token + RBAC）。为保持零外部依赖，用标准库 BaseHTTPRequestHandler。
"""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from ..config import AppConfig
from ..runtime import Runtime
from ..security.access import AccessDenied, PolicyEngine

_API_TOKENS: Dict[str, Dict[str, str]] = {
    # 演示令牌：token -> {identity, role}
    "demo-analyst-token": {"identity": "demo-analyst", "role": "analyst"},
    "demo-lead-token": {"identity": "demo-lead", "role": "soc_lead"},
    "demo-admin-token": {"identity": "demo-admin", "role": "admin"},
}


class AegisflowHandler(BaseHTTPRequestHandler):
    runtime: Runtime = None  # type: ignore[assignment]
    policy: PolicyEngine = None  # type: ignore[assignment]
    tls: Optional[ssl.SSLContext] = None

    # ---- plumbing ------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:
        return  # 关闭默认访问日志（避免输出敏感信息）

    def _send(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> Dict[str, str]:
        """极简 Bearer 鉴权（生产置于 mTLS/网关后）。"""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise AccessDenied("missing bearer token")
        tok = auth[len("Bearer "):].strip()
        subj = _API_TOKENS.get(tok)
        if not subj:
            raise AccessDenied("invalid token")
        return subj

    # ---- routes ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        try:
            subject = self._auth()
        except AccessDenied as e:
            self._send(403, {"error": str(e)})
            return
        rt: Runtime = self.runtime
        path = self.path.split("?")[0]
        try:
            if path == "/status":
                self._send(200, {"ok": True, "status": rt.stats()})
            elif path == "/health":
                # HA 探活：无鉴权也可（由探针使用），返回 200 即存活
                self._send(200, {"ok": True})
            elif path == "/incidents":
                self.policy.check(subject, "read", "incident")
                data = rt.incidents
                data = [self._mask(subject, "incident", d) for d in data]
                self._send(200, {"incidents": data, "count": len(data)})
            elif path == "/policies":
                self.policy.check(subject, "read", "config")
                self._send(200, self.policy.policy_snapshot())
            elif path == "/rules":
                self._send(200, {"rules": rt.pipeline.rules.catalog()})
            elif path == "/audit/verify":
                self.policy.check(subject, "read", "audit")
                problems = rt.audit.verify()
                self._send(200, {"integrity_ok": not problems, "problems": problems})
            elif path == "/audit/recent":
                self.policy.check(subject, "read", "audit")
                self._send(200, {"audit": rt.audit.recent()})
            else:
                self._send(404, {"error": "not found"})
        except AccessDenied as e:
            self._send(403, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})

    def do_POST(self) -> None:  # noqa: N802
        try:
            subject = self._auth()
        except AccessDenied as e:
            self._send(403, {"error": str(e)})
            return
        rt: Runtime = self.runtime
        path = self.path.split("?")[0]
        try:
            if path == "/events":
                self.policy.check(subject, "read", "event")
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b"{}"
                payload = json.loads(body or b"{}")
                ok = rt.ingest_raw(payload)
                self._send(200, {"accepted": ok})
            else:
                self._send(404, {"error": "not found"})
        except AccessDenied as e:
            self._send(403, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(400, {"error": str(e)})

    def _mask(self, subject: Dict[str, str], resource: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self.policy.filter_fields(subject.get("role", ""), resource, data)


def serve(runtime: Runtime, cfg: AppConfig) -> ThreadingHTTPServer:
    """启动管理平面 HTTP 服务（可选 TLS1.3 mTLS）。"""
    handler = AegisflowHandler
    handler.runtime = runtime
    handler.policy = runtime.policy
    server = ThreadingHTTPServer((cfg.api.host, cfg.api.port), handler)

    if cfg.tls.cert_path and cfg.tls.key_path and cfg.tls.ca_path:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg.tls.cert_path, cfg.tls.key_path)
        ctx.load_verify_locations(cafile=cfg.tls.ca_path)
        ctx.verify_mode = _ssl.CERT_REQUIRED         # mTLS 双向
        try:
            ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
        except Exception:  # noqa: BLE001
            pass
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
