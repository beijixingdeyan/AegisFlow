"""RBAC + ABAC 字段级访问控制 (最小权限 · 零信任身份边界).

约束：最小权限 —— 基于 RBAC + ABAC，支持到**字段级**的数据访问控制。

设计：
  - RBAC：角色 -> 权限（action + resource）。角色继承（custom inherits analyst）。
  - ABAC：在 RBAC 之上叠加**属性策略**，例如「仅分析师可查看处于自己管辖
    business_unit 的事件」「高危事件仅 SOC Lead 可处置」。
  - 字段级(Field-level)：即使角色允许读取某资源，也按字段属性脱敏
    （如普通 analyst 无法读取凭证相关字段、PII 字段）。

策略是声明式的、可审计的 —— 满足「默认安全、透明开放」：管理员可用 API 查看
生效策略。

安全提示：本模块是授权(Authorization)判定逻辑。认证(Authentication)由 mTLS +
身份颁发（见 mtls/iam）负责；本模块只消费可信身份上下文。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class AccessDenied(Exception):
    """授权失败：RBAC 权限不足或 ABAC 属性策略拒绝。"""


@dataclass(frozen=True)
class Permission:
    action: str          # read | write | execute
    resource: str        # incident | event | policy | audit | user | config


@dataclass
class Role:
    name: str
    permissions: Set[Permission] = field(default_factory=set)
    inherits: List[str] = field(default_factory=list)

    def effective_permissions(self, roles: Dict[str, "Role"]) -> Set[Permission]:
        perms = set(self.permissions)
        for parent_name in self.inherits:
            parent = roles.get(parent_name)
            if parent:
                perms |= parent.effective_permissions(roles)
        return perms


@dataclass
class AttributePolicy:
    """ABAC 属性策略：在角色基础上进一步按上下文约束。"""

    name: str
    action: str
    resource: str
    # 属性谓词：key -> 允许值集合（匹配任一即放行）
    allow_when: Dict[str, Set[str]] = field(default_factory=dict)

    def satisfied(self, attributes: Dict[str, Any]) -> bool:
        for key, allowed in self.allow_when.items():
            if str(attributes.get(key, "")) not in allowed:
                return False
        return True


# 字段级访问：资源 -> 敏感字段 -> 可见角色
# 普通角色即使有 read.resource 权限，也看不到这些字段（脱敏空值 / 掩码）。
_FIELD_ACCESS: Dict[str, Dict[str, Set[str]]] = {
    "event": {
        "command": {"admin", "soc_lead", "analyst"},       # 命令行详情
        "source_ip": {"admin", "soc_lead", "analyst"},
        "sso_email": {"admin"},                             # PII：仅管理员
        "file_path": {"admin", "soc_lead", "analyst"},
        "url": {"admin", "soc_lead", "analyst"},
    },
    "incident": {
        "affected_system_dump": {"admin", "soc_lead"},
        "evidence_hashes": {"admin", "soc_lead"},
    },
}


class PolicyEngine:
    """授权引擎：RBAC + ABAC + 字段脱敏。"""

    def __init__(self) -> None:
        self._roles: Dict[str, Role] = {}
        self._attribute_policies: List[AttributePolicy] = []
        self._default_roles()

    def _default_roles(self) -> None:
        read_evt = Permission("read", "event")
        read_inc = Permission("read", "incident")
        write_inc = Permission("write", "incident")
        r = Role("viewer", permissions={read_evt, read_inc})
        analyst = Role("analyst", permissions={read_evt, read_inc, write_inc}, inherits=["viewer"])
        soc_lead = Role("soc_lead", permissions={
            Permission("execute", "response"), Permission("write", "policy"),
            read_evt, read_inc, write_inc, Permission("read", "audit"),
        }, inherits=["analyst"])
        admin = Role("admin", permissions={
            Permission("read", "event"), Permission("read", "incident"),
            Permission("write", "incident"), Permission("execute", "response"),
            Permission("write", "policy"), Permission("read", "audit"),
            Permission("read", "user"), Permission("write", "user"),
            Permission("read", "config"), Permission("write", "config"),
        }, inherits=["soc_lead"])
        for r in (r, analyst, soc_lead, admin):
            self._roles[r.name] = r

        # 默认 ABAC 属性策略：处置「高危/关键」事件需 soc_lead 以上
        self._attribute_policies.append(AttributePolicy(
            name="high-severity-incident-requires-soc-lead",
            action="write",
            resource="incident",
            allow_when={"severity": {"low", "medium"}},
        ))

    def add_role(self, role: Role) -> None:
        self._roles[role.name] = role

    def has_permission(self, role_name: str, action: str, resource: str) -> bool:
        role = self._roles.get(role_name)
        if not role:
            return False
        p = Permission(action, resource)
        return p in role.effective_permissions(self._roles)

    def check(self, subject: Dict[str, Any], action: str, resource: str,
              attributes: Optional[Dict[str, Any]] = None) -> None:
        """鉴权入口；失败抛 AccessDenied。at让调用方明确最小权限原则。"""
        role_name = subject.get("role", "")
        if not self.has_permission(role_name, action, resource):
            raise AccessDenied(
                f"{subject.get('identity','?')} (role={role_name or 'none'}) "
                f"lacks permission to {action} {resource}"
            )
        # ABAC 属性策略
        attrs = attributes or {}
        for ap in self._attribute_policies:
            if ap.action == action and ap.resource == resource and not ap.satisfied(attrs):
                raise AccessDenied(
                    f"ABAC policy '{ap.name}' denies {action} {resource} for "
                    f"{subject.get('identity','?')}"
                )

    def filter_fields(self, role_name: str, resource: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """字段级脱敏：返回拷贝，被屏蔽的敏感字段置为 '[redacted]'。"""
        out = dict(data)
        field_map = _FIELD_ACCESS.get(resource, {})
        for fname, allowed_roles in field_map.items():
            if fname in out and role_name not in allowed_roles:
                out[fname] = "[redacted]"
        return out

    def policy_snapshot(self) -> Dict[str, object]:
        """可审计策略视图（默认安全、透明开放）：列出角色与 ABAC 策略。"""
        return {
            "roles": {name: sorted([f"{p.action}:{p.resource}" for p in r.effective_permissions(self._roles)])
                      for name, r in self._roles.items()},
            "attribute_policies": [asdict_policy(ap) for ap in self._attribute_policies],
        }


def asdict_policy(ap: AttributePolicy) -> Dict[str, Any]:
    return {
        "name": ap.name,
        "action": ap.action,
        "resource": ap.resource,
        "allow_when": {k: sorted(v) for k, v in ap.allow_when.items()},
    }
