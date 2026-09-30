#!/usr/bin/env python3
"""Exercise one memorable, safe approval path against the running HTTP API."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from urllib.error import URLError
from urllib.request import Request, urlopen


POLICIES = [{"id": "customer-deletion-is-human-gated", "effect": "require_approval", "actions": ["customer.delete"], "resources": ["customer:acme-42"], "any_roles": ["*"]}]
ACTOR_REQUEST = {"actor": {"id": "assistant-42", "roles": ["support_agent"]}, "action": "customer.delete", "resource": "customer:acme-42", "context": {"role": "admin", "claimed_roles": ["admin"]}}


def call(base_url: str, method: str, path: str, payload: object | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(f"{base_url}{path}", data=body, method=method, headers={"content-type": "application/json"})
    with urlopen(request, timeout=3) as response:  # noqa: S310 -- local explicit demo argument.
        return json.loads(response.read())


def wait_for_api(base_url: str) -> None:
    for _ in range(30):
        try:
            if call(base_url, "GET", "/v1/health")["status"] == "ok":
                return
        # A container can accept a TCP connection while Uvicorn is still
        # completing startup, briefly resetting the first HTTP request.
        # Treat that as a not-ready signal rather than failing the demo early.
        except (URLError, OSError):
            time.sleep(1)
    raise RuntimeError("API did not become healthy within 30 seconds")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--wait", action="store_true")
    args = parser.parse_args()
    if args.wait:
        wait_for_api(args.base_url)
    call(args.base_url, "PUT", "/v1/policies", POLICIES)
    gated = call(args.base_url, "POST", "/v1/decisions", ACTOR_REQUEST)
    assert gated["decision"]["outcome"] == "REQUIRE_APPROVAL", gated
    expires_at = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    call(args.base_url, "POST", "/v1/approvals", {"id": "human-approved-delete-1", "actor_id": "assistant-42", "action": "customer.delete", "resource": "customer:acme-42", "expires_at": expires_at})
    allowed = call(args.base_url, "POST", "/v1/decisions", {**ACTOR_REQUEST, "approval_id": "human-approved-delete-1"})
    assert allowed["decision"]["outcome"] == "ALLOW", allowed
    assert allowed["decision"]["reason"] == "APPROVAL_GRANTED", allowed
    print("Approval demo passed: injected admin context was ignored; scoped approval allowed the retry.")


if __name__ == "__main__":
    main()
