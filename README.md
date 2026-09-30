# Governed Policy Engine

A small, deterministic authorization service for AI-enabled systems. It decides
whether a request is **allowed**, **denied**, or **requires human approval**,
then emits an integrity-protected audit event. It does not execute tools, call
models, or infer permissions from prompt text.

## Why it exists

LLMs can recommend actions. They should not be the authority that grants those
actions. This project makes the control plane explicit:

```text
actor + request -> deterministic policy evaluation -> decision
                         |                         |
                         +--> append-only audit <---+
```

The policy engine uses only declared actor roles, policy rules, request fields,
and an injected clock. It ignores untrusted role-like data in request context.

## Run in under five minutes

Prerequisites: Docker and Docker Compose.

```bash
cp .env.example .env
docker compose up --build
```

In a second terminal:

```bash
curl -s http://localhost:8000/v1/health
curl -s -X PUT http://localhost:8000/v1/policies \
  -H 'content-type: application/json' \
  -d @examples/policies.json
curl -s -X POST http://localhost:8000/v1/decisions \
  -H 'content-type: application/json' \
  -d @examples/allowed_request.json
```

Interactive API documentation is available at `http://localhost:8000/docs`.
Run the tests locally with `python -m pytest`.

## One end-to-end demo

The included approval flow shows why this is useful for AI-enabled software:

```text
assistant requests customer.delete + supplies {"role": "admin"} in untrusted context
        -> REQUIRE_APPROVAL (context did not change identity)
human records a scoped approval for that actor, action, and resource
same request + approval ID
        -> ALLOW, with a signed audit event for each decision
```

With the service running, execute:

```bash
python scripts/approval_demo.py --wait
```

The approval API is intentionally a demo boundary. A production deployment must
authenticate and authorize the human approver before it records an approval.

## Decision semantics

1. Invalid policies fail closed (`DENY`).
2. Expired policies do not match.
3. Matching explicit deny policies win.
4. Matching approval policies return `REQUIRE_APPROVAL` unless a valid approval
   ID is supplied.
5. Matching allow policies return `ALLOW`; otherwise the engine defaults to
   `DENY`.

Policy order is deliberately not an authority mechanism. Within the same effect,
the most specific matching rule is selected; ties use a stable policy ID sort.

## Example policy

```json
{
  "id": "deploy-production",
  "effect": "require_approval",
  "actions": ["deployment.release"],
  "resources": ["environment:production"],
  "any_roles": ["release_manager"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
`examples/` for complete scenarios. This is a demonstration control plane, not
a substitute for a production identity provider, key-management system, or
security review.
