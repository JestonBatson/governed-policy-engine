from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import AuditLog
from .engine import Decision, PolicyEngine
from .models import Actor, Approval, Policy, Request

app = FastAPI(title="Governed Policy Engine", version="0.1.0")


class ActorInput(BaseModel):
    id: str = Field(min_length=1)
    roles: list[str] = Field(min_length=1)


class RequestInput(BaseModel):
    actor: ActorInput
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class PolicyInput(BaseModel):
    id: str = Field(min_length=1)
    effect: Literal["allow", "deny", "require_approval"]
    actions: list[str] = Field(min_length=1)
    resources: list[str] = Field(min_length=1)
    any_roles: list[str] = Field(min_length=1)
    expires_at: datetime | None = None


class ApprovalInput(BaseModel):
    id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    expires_at: datetime


def _policy(item: PolicyInput) -> Policy:
    return Policy(item.id, item.effect, tuple(item.actions), tuple(item.resources), tuple(item.any_roles), item.expires_at)


engine = PolicyEngine(())


def _audit() -> AuditLog:
    try:
        return AuditLog(os.getenv("AUDIT_LOG_PATH", "var/audit.jsonl"), os.getenv("AUDIT_SIGNING_KEY", ""))
    except ValueError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.put("/v1/policies")
def set_policies(items: list[PolicyInput]) -> dict[str, int]:
    global engine
    engine = PolicyEngine(_policy(item) for item in items)
    return {"policy_count": len(items)}


@app.post("/v1/approvals")
def add_approval(item: ApprovalInput) -> dict[str, str]:
    engine.record_approval(Approval(**item.model_dump()))
    return {"approval_id": item.id}


@app.post("/v1/decisions")
def decide(item: RequestInput) -> dict[str, Any]:
    request = Request(Actor(item.actor.id, tuple(item.actor.roles)), item.action, item.resource, item.context, item.approval_id)
    decision: Decision = engine.evaluate(request)
    event = _audit().append(
        {
            "actor_id": request.actor.id,
            "actor_roles": list(request.actor.roles),
            "action": request.action,
            "resource": request.resource,
            "decision": decision.as_dict(),
        }
    )
    return {"decision": decision.as_dict(), "audit_event": event}
