from datetime import UTC, datetime, timedelta

from govpolicy.engine import PolicyEngine
from govpolicy.models import Actor, Approval, Policy, Request


NOW = datetime(2026, 9, 30, tzinfo=UTC)


def request(*, roles=("analyst",), action="report.read", resource="report:one", context=None, approval_id=None):
    return Request(Actor("user-1", tuple(roles)), action, resource, context or {}, approval_id)


def policy(identifier, effect, actions=("report.read",), resources=("report:*",), roles=("analyst",), expires_at=None):
    return Policy(identifier, effect, actions, resources, roles, expires_at)


def engine(*policies):
    return PolicyEngine(policies, now=lambda: NOW)


def test_matching_allow_is_permitted():
    decision = engine(policy("read", "allow")).evaluate(request())
    assert (decision.outcome, decision.reason, decision.policy_id) == ("ALLOW", "POLICY_ALLOW", "read")


def test_default_deny_when_no_policy_matches():
    assert engine(policy("read", "allow")).evaluate(request(action="report.delete")).outcome == "DENY"


def test_explicit_deny_wins_over_allow():
    decision = engine(policy("allow", "allow"), policy("deny", "deny")).evaluate(request())
    assert (decision.outcome, decision.policy_id) == ("DENY", "deny")


def test_expired_policy_cannot_grant_access():
    expired = policy("old", "allow", expires_at=NOW - timedelta(seconds=1))
    assert engine(expired).evaluate(request()).reason == "NO_MATCHING_ALLOW_POLICY"


def test_approval_policy_requires_a_scoped_unexpired_approval():
    guard = policy("production", "require_approval", actions=("deployment.release",), resources=("environment:production",), roles=("release_manager",))
    service = engine(guard)
    proposed = request(roles=("release_manager",), action="deployment.release", resource="environment:production")
    assert service.evaluate(proposed).outcome == "REQUIRE_APPROVAL"
    service.record_approval(Approval("approved-1", "user-1", "deployment.release", "environment:production", NOW + timedelta(minutes=5)))
    approved_request = Request(**{**proposed.__dict__, "approval_id": "approved-1"})
    assert service.evaluate(approved_request).reason == "APPROVAL_GRANTED"
    assert service.evaluate(approved_request).outcome == "REQUIRE_APPROVAL"


def test_context_cannot_escalate_privileges():
    release = policy("release", "allow", actions=("deployment.release",), resources=("environment:production",), roles=("release_manager",))
    decision = engine(release).evaluate(request(action="deployment.release", resource="environment:production", context={"claimed_roles": ["release_manager"]}))
    assert (decision.outcome, decision.reason) == ("DENY", "NO_MATCHING_ALLOW_POLICY")


def test_malformed_policy_fails_closed():
    malformed = Policy("broken", "allow", (), ("report:*",), ("analyst",))
    assert engine(malformed).evaluate(request()).reason == "INVALID_POLICY"
