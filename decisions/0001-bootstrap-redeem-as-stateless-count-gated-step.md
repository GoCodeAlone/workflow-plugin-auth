# 0001. Bootstrap redeem as a stateless, count-gated auth step

**Status:** Accepted
**Date:** 2026-06-02
**Decision-makers:** Jon Langevin (codingsloth@pm.me), autodev pipeline
**Related:** `docs/plans/2026-06-02-auth-bootstrap-redeem-design.md`, issue #23, prior `docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md` (§Phase II)

## Context

Issue #23 asked for an embeddable `auth.NewHandler` http facade + bootstrap-code
redeem so a fresh admin deploy can be logged in the first time, then upgrade to
passkey/SSO. The plugin is a stateless, engine-mediated step library — credentials,
sessions, HTTP routing and DB all live in the consumer's workflow pipeline (see
`step_credential.go`, `step_magic_link.go`). The stated #23 consumer
(gocodealone-multisite) never imported the plugin; it shipped a bespoke
`admin_bootstrap.go` whose bootstrap code is a *permanent reusable shared secret*
that mints a stateless JWT — it never closes and offers no passkey/SSO upgrade. A
durable, reusable replacement is needed, and must be demonstrated.

## Decision

Ship `step.auth_bootstrap_redeem` as a **stateless step in workflow-plugin-auth**,
gated by `existing_admin_count == 0` (supplied by the consumer via `db_query`),
constant-time code compare, fail-safe-closed on any non-zero/missing count. Bootstrap
is OPEN ⟺ zero admin credentials exist. *Rejected:* (a) http.Handler facade owning
routes/sessions/persistence — fights the stateless engine model, no consumer needs
it; (b) a new `workflow-plugin-admin-bootstrap` plugin — fragments the auth surface;
(c) a one-shot **consumed token** — cannot recover from credential loss, whereas the
count-gate re-opens on an empty store for break-glass recovery; (d) operator seeds the
super-admin row directly via SQL at deploy time (BMW PR-2 pattern) — rejected: requires
DB access at deploy, and has no mechanism to *close* the path after passkey enrolment
(the count-gate auto-closes). The auth plugin is
the home because bootstrap is an auth-credential primitive and the 2026-05-17 design
pre-committed it for v0.3.0.

## Consequences

- (+) Auto-closes on first passkey/SSO enrolment; stays closed on redeploy with the same DB; re-opens for break-glass recovery. Durable without a one-shot token's irreversibility.
- (+) Plugin stays stateless; no DB/session ownership added; composes with existing passkey/oauth/credential steps.
- (−) Correctness depends on the consumer wiring `existing_admin_count` accurately; mitigated by default-deny when the count is missing/ambiguous and by a scenario that proves the wiring.
- (−) No plugin-side session issuer; consumers mint sessions (e.g. modular `auth.jwt`) — JWT issuer remains deferred to Phase II.
- Migration cost: consumers adopt by adding a count `db_query` + the step; gocodealone-multisite migration is a tracked follow-up.
