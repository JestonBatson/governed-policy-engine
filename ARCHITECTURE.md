# Architecture

## Boundary

`govpolicy` is a **decision service**. It accepts already-authenticated actor
attributes from a trusted caller and returns an authorization decision. Tool
execution belongs to a separate component that must enforce the returned
decision and preserve the audit event ID.

```text
trusted identity provider
          |
          v
  Decision API -> Policy evaluator -> ALLOW | DENY | REQUIRE_APPROVAL
          |                  |                         |
          +------------------+---- signed audit event --+
```

## Core invariants

- Default deny; an absent or malformed policy never permits an action.
- Authorization relies on `actor.roles`, never role-like request context.
- An explicit deny overrides allow or approval.
- Approval is scoped to actor, action, and resource, time-bounded, single-use,
  and checked before the request may be allowed.
- Events are append-only JSONL and HMAC-signed. A verifier can detect local
  modification when it has the signing key.
- The evaluator is deterministic for equal policy/request/clock inputs.

## Deliberate omissions

The starter service does not authenticate HTTP callers, manage users, encrypt
audit storage, rotate signing keys, or execute actions. In production, place it
behind authenticated service-to-service transport; source attributes from an
identity provider; use KMS/HSM-backed rotating keys; store audit data in an
immutable/retained system; and enforce decisions at the tool boundary.
