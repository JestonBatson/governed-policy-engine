from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


Effect = Literal["allow", "deny", "require_approval"]
Outcome = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class Actor:
    id: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class Request:
    actor: Actor
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    approval_id: str | None = None


@dataclass(frozen=True)
class Policy:
    id: str
    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    any_roles: tuple[str, ...]
    expires_at: datetime | None = None


@dataclass(frozen=True)
class Approval:
    id: str
    actor_id: str
    action: str
    resource: str
    expires_at: datetime
    consumed: bool = False
