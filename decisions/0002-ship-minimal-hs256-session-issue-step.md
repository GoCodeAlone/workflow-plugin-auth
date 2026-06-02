# 0002. Ship a minimal HS256 `step.auth_jwt_issue` now; defer the full IDP

**Status:** Accepted
**Date:** 2026-06-02
**Decision-makers:** Jon Langevin (codingsloth@pm.me), autodev pipeline
**Related:** `docs/plans/2026-06-02-auth-bootstrap-redeem-design.md` (rev 3), ADR-0001, `docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md` (§Phase II), adversarial cycle-2 (C2-1/C2-2/C2-3)

## Context

The durable-bootstrap demo must show "logged in after redeem" and "subsequent passkey
login" — both require minting a session token for a verified principal. Adversarial
cycle-2 proved (by grepping every engine `StepFactories()`) that there is **no
in-pipeline JWT-issue step**: `step.m2m_token`/`step.auth_required` are schema-only
metadata with no runtime factory; minting lives only inside `auth.jwt`/`auth.m2m` HTTP
handlers (password or client-creds grants — neither fits a passwordless admin session).
The only real runtime auth steps are `step.auth_validate` (gate) and `step.token_revoke`
(logout). Every existing consumer rolls a bespoke mint (BMW `step.bmw.generate_token`,
multisite `modular auth.Service.GenerateToken`). The 2026-05-17 design deferred a plugin
JWT issuer to "Phase II v0.4.0," but the new requirement (a self-contained, durable,
reusable bootstrap that *replaces* multisite's bespoke mint) makes the mint primitive
load-bearing now.

## Decision

Ship a **minimal `step.auth_jwt_issue`** in v0.3.0: HS256 symmetric signing from
`{subject, claims}` with a shared-secret env var, emitting standard claims
(`sub,iat,exp,iss,jti`). It is validated by the engine's existing `step.auth_validate`
against an `auth.jwt` module sharing the secret (`JWTAuthModule.Authenticate` is
signature-only HS256 — verified). **Defer to Phase II** (a separate `auth.idp` design):
JWKS endpoint, refresh tokens, asymmetric/ES256 keys, key rotation. *Rejected:* (a)
reuse `auth.m2m`'s `/oauth/token` via `step.http_call` — client-credentials mints the
client's identity not the admin's, and the unexported `issueToken` isn't reachable with
arbitrary subject+claims without a pre-signed assertion; (b) seed a password into
`auth.jwt` and call `/login` — not passwordless; (c) let the scenario test mint the
token inline (scenario-92 bash pattern) — proves the gate but not the *app's* mint, so
the demo wouldn't actually exercise the capability a consumer needs.

## Consequences

- (+) The demo is 100% real runtime (issue + validate + revoke all exist); no fictional steps.
- (+) The plugin now offers the portable mint that lets it *fully* replace bespoke consumer token issuers — directly serving the "replace multisite" goal.
- (+) Small, well-bounded surface (HS256 sign ~40 LOC + proto + tests); composes with passkey/oauth/credential steps.
- (−) Two new steps in v0.3.0 instead of one — larger blast radius; both go through the same contract/manifest discipline.
- (−) HS256 symmetric only: every validator must share the secret. Asymmetric/JWKS multi-service verification waits for Phase II. Documented as a non-goal, not a silent gap.
- Migration: consumers adopt `auth_jwt_issue` to retire bespoke mints; tracked per-consumer (multisite migration is a post-merge follow-up).
