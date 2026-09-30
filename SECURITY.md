# Security notes

## Threats addressed

- **Prompt/context privilege injection:** request context is not consulted for
  roles; tests demonstrate that `context.claimed_roles` cannot grant access.
- **Stale authorization:** policies and approval grants have UTC expiry times.
- **Ambiguous authorization:** validation failures and unmatched requests deny.
- **Allow-rule bypass:** explicit deny takes precedence.
- **Audit tampering:** every emitted event includes an HMAC-SHA-256 signature.

## Operational requirements

Use a randomly generated `AUDIT_SIGNING_KEY` supplied by a secret manager. Do
not commit `.env`, audit logs, approval records, or production policies. The
development compose configuration creates only local state under `./var/`.

HMAC makes tampering evident to a verifier holding the key; it does not make a
local log immutable. Production deployments need remote append-only retention,
access control, key rotation, and monitoring.

## Disclosure

Please do not open public issues containing credentials or production policy
data. Report security concerns privately to the repository owner.
