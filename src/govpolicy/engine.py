from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Callable, Iterable

from .models import Approval, Outcome, Policy, Request


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    policy_id: str | None
    approval_id: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


class PolicyEngine:
    """Pure, deterministic policy evaluator. It never executes the request."""

    def __init__(self, policies: Iterable[Policy], now: Callable[[], datetime] | None = None):
        self._policies = tuple(policies)
        self._now = now or (lambda: datetime.now(UTC))
        self._approvals: dict[str, Approval] = {}

    def record_approval(self, approval: Approval) -> None:
        self._approvals[approval.id] = approval

    def evaluate(self, request: Request) -> Decision:
        invalid = self._invalid_policy()
        if invalid:
            return Decision("DENY", "INVALID_POLICY", invalid.id)
        matches = [policy for policy in self._policies if self._matches(policy, request)]
        for effect, outcome, reason in (
            ("deny", "DENY", "EXPLICIT_DENY"),
            ("require_approval", "REQUIRE_APPROVAL", "HUMAN_APPROVAL_REQUIRED"),
            ("allow", "ALLOW", "POLICY_ALLOW"),
        ):
            choices = [policy for policy in matches if policy.effect == effect]
            if not choices:
                continue
            policy = max(choices, key=self._specificity)
            if effect == "require_approval":
                approval = self._usable_approval(request)
                if approval:
                    self._approvals[approval.id] = replace(approval, consumed=True)
                    return Decision("ALLOW", "APPROVAL_GRANTED", policy.id, request.approval_id)
            return Decision(outcome, reason, policy.id, request.approval_id)
        return Decision("DENY", "NO_MATCHING_ALLOW_POLICY", None)

    def _invalid_policy(self) -> Policy | None:
        for policy in self._policies:
            if (
                not policy.id
                or policy.effect not in {"allow", "deny", "require_approval"}
                or not policy.actions
                or not policy.resources
                or not policy.any_roles
            ):
                return policy
        return None

    def _matches(self, policy: Policy, request: Request) -> bool:
        now = self._now()
        if policy.expires_at and _utc(policy.expires_at) <= _utc(now):
            return False
        return (
            any(fnmatchcase(request.action, pattern) for pattern in policy.actions)
            and any(fnmatchcase(request.resource, pattern) for pattern in policy.resources)
            and ("*" in policy.any_roles or bool(set(request.actor.roles) & set(policy.any_roles)))
        )

    def _usable_approval(self, request: Request) -> Approval | None:
        if not request.approval_id:
            return None
        approval = self._approvals.get(request.approval_id)
        if (
            approval
            and not approval.consumed
            and _utc(approval.expires_at) > _utc(self._now())
            and approval.actor_id == request.actor.id
            and approval.action == request.action
            and approval.resource == request.resource
        ):
            return approval
        return None

    @staticmethod
    def _specificity(policy: Policy) -> tuple[int, str]:
        literal = sum(len(value.replace("*", "")) for value in (*policy.actions, *policy.resources, *policy.any_roles))
        return literal, policy.id


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
