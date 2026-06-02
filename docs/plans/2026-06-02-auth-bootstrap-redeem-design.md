# Durable First-Run Admin Bootstrap — Design (2026-06-02)

Issue: GoCodeAlone/workflow-plugin-auth#23. Supersedes the http-facade framing of #23
(overtaken: gocodealone-multisite never imported the plugin; rolled bespoke
`cmd/multisite-host/admin_bootstrap.go`). Realises the "Phase II — reusable plugin
extraction" earmarked in `docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md`
(trigger = "second consumer materialises"; now fired).

## §G — Goal

Reusable, durable first-run admin login: fresh deploy → operator redeems an
out-of-band seeded code → super-admin session → enrols **passkey** (or links
**SSO**) as PRIMARY credential → bootstrap path **auto-closes**. Durable across
restarts/redeploys; re-opens only when the credential store is empty (break-glass
recovery). Replaces the multisite anti-pattern (permanent reusable shared secret →
stateless JWT, no upgrade path, no persistence). Prove end-to-end in a
workflow-scenarios admin stack.

## §C — Constraints / Global Design Guidance

Guidance: none found (`docs/design-guidance.md` absent in repo/workspace/engine);
durable constraints captured here from SPEC.md + prior design docs + user Q&A.

| guidance (source) | design response |
|---|---|
| Engine-mediated step model; plugin is STATELESS, persistence is consumer-pipeline-owned (`step_credential.go` "Pipeline does the DB query, this step formats output"; `step_magic_link.go` consumption is consumer-DB) | New step holds NO state. Takes `existing_admin_count` as INPUT (consumer supplies via `db_query`); never queries a DB itself. |
| General-purpose, serves N consumers; per-consumer config not code deletion (SPEC C1) | Code source + super-admin identity are config/env per consumer; no consumer hard-coded. |
| Strict gRPC proto contracts; manifest aligned to runtime (`wfctl plugin verify-capabilities`, SPEC C5) | Add typed `BootstrapRedeem{Config,Input,Output}` proto + STRICT_PROTO contract; register in `plugin.json` stepTypes + capabilities.stepTypes. |
| Prior design earmarked `auth.bootstrap` for v0.3.0 (2026-05-17 §Phase II) | Ship as a step in workflow-plugin-auth (NOT a new plugin, NOT an http facade). |
| Secrets never in YAML; env-sourced (magic-link `configStrOrEnv` precedent) | Code read from env (`AUTH_BOOTSTRAP_CODE` default; name overridable). YAML carries only the env-var NAME + super-admin identity. |

### Home-repo determination (user asked: aligned step vs new plugin)

**Decision: a step in workflow-plugin-auth.** See `decisions/0001-bootstrap-redeem-as-stateless-count-gated-step.md`.
Bootstrap = "establish first auth identity + first credential" = an auth-credential primitive. Composes with existing
`step.auth_passkey_*` / `step.auth_oauth_*` / `step.auth_credential_*`. The repo's
own 2026-05-17 design pre-committed this. *Considered + rejected:* a dedicated
`workflow-plugin-admin-bootstrap` — fragments the auth surface, duplicates
credential plumbing, no benefit. *Considered + rejected:* http.Handler facade owning
routes/sessions/persistence (the literal #23 ask) — fights the stateless engine model
and no consumer needs it.

## §I — Interface

### New step `step.auth_bootstrap_redeem`

```
config:
  super_admin_email:  string            # identity minted on first redeem
  super_admin_role:   string (= "super_admin")
  code_env:           string (= "AUTH_BOOTSTRAP_CODE")  # env var NAME holding the code
  min_code_length:    int    (= 16)     # reject too-short configured codes (defence)
input:
  code:                 string           # operator-submitted code (from request body)
  existing_admin_count: int32            # consumer supplies via preceding db_query
output:
  redeemed:  bool
  email:     string                      # set iff redeemed
  role:      string                      # set iff redeemed
  reason:    string                      # "" | "bootstrap_closed" | "invalid_code" | "not_configured"
  error:     string (field 100)          # only for hard/internal errors
```

**Logic (stateless, fail-safe-closed):**
1. Code unresolved (env empty) OR `len(code_env-value) < min_code_length` → `{redeemed:false, reason:"not_configured"}`.
2. `existing_admin_count` not explicitly `0` (missing / negative / >0) → `{redeemed:false, reason:"bootstrap_closed"}`. **Default-deny.**
3. `existing_admin_count == 0` AND `constantTimeEqual(code, envCode)` → `{redeemed:true, email, role}`.
4. `existing_admin_count == 0` AND mismatch → `{redeemed:false, reason:"invalid_code"}`.

`constantTimeEqual` = length-guard + `subtle.ConstantTimeCompare` (mirrors multisite
`admin_bootstrap.go:213`).

### Core invariant (the design's headline)

> **Bootstrap is OPEN ⟺ zero admin credentials exist.**

Beats both alternatives: multisite's permanent secret never closes; a one-shot
consumed token can't recover from credential loss. Count-gate auto-closes on first
passkey/SSO enrolment, stays closed on redeploy (same DB → count>0), and re-opens for
break-glass if the store is ever emptied (count→0).

### Consumer wiring (demonstrated, not shipped in the plugin)

```
POST /admin/bootstrap/redeem:
  request_parse(body)                       → .code
  db_query count_admin_credentials          → existing_admin_count   (SELECT count(*) ... kind IN ('passkey','google','facebook') / role super_admin)
  step.auth_bootstrap_redeem {code, existing_admin_count}
  conditional .redeemed:
    db_exec INSERT super-admin user ON CONFLICT(email) DO NOTHING     (idempotent)
    auth.jwt issue session cookie
    → 200
  else → 403 {reason}
```
Enrol-primary reuses existing passkey/oauth steps; once a credential row lands,
`count_admin_credentials > 0` → subsequent redeems hit reason `bootstrap_closed`.

## §V — Invariants (backport to SPEC.md)

- V-B1: bootstrap redeem succeeds only when `existing_admin_count == 0`; any other value (incl. missing) → denied.
- V-B2: code compared constant-time; configured code shorter than `min_code_length` → `not_configured` (never matches).
- V-B3: plugin step writes no state; never opens a DB/socket; identity persistence + session minting are consumer-owned.
- V-B4: once ≥1 admin credential exists, no code value can re-open bootstrap (durable close).
- V-B5: redeem output never echoes the configured code or env value.

## Security Review

- **AuthZ/authn:** the code is the sole secret; gate is the count==0 precondition. Leaked code is INERT once closed (V-B4). Constant-time compare + length guard. Default-deny on ambiguous count.
- **Secrets/logging:** code from env only; never logged; never in output (V-B5). YAML holds only the env NAME + super-admin email (non-secret).
- **Abuse:** brute force only possible while count==0 (pre-first-admin window). Mitigations: ≥16-char code (config-enforced), constant-time compare, consumer SHOULD rate-limit the redeem route (documented). Window is short (closes on first enrolment).
- **Concurrent redeem (count==0):** two simultaneous redeems both pass step → consumer `INSERT ... ON CONFLICT(email) DO NOTHING` converges to one super-admin; harmless.
- **Least privilege:** minted role is exactly `super_admin` (configurable); no broader grant.
- **Trust boundary / deps:** no new external deps (uses stdlib `crypto/subtle`). gRPC contract is STRICT_PROTO like every sibling step.

## Infrastructure Impact

- **Plugin:** additive step + proto message + manifest entries. New release tag **v0.3.0** (minor: additive new step). `minEngineVersion` unchanged (0.57.2; same SDK surface). `version`/`downloads` stay version-discipline placeholders (release workflow templates them).
- **Registry:** workflow-registry manifest capabilities gain the new step (so `verify-capabilities` matches runtime).
- **Scenario:** new isolated docker-compose stack (engine + plugin + Postgres); own scenario namespace/ports; no shared-state impact on other scenarios. No cloud resources.
- **Migrations:** none in the plugin. The scenario seed creates `users` + `credentials` tables (scenario-local).
- **Deploy/rollback:** see §Rollback. No prod approval needed (public plugin + test scenario).

## Multi-Component Validation

Real boundaries, no mock-only proof: **engine ↔ plugin (gRPC) ↔ Postgres ↔ HTTP**.
Scenario `NN-auth-admin-bootstrap` boots the real workflow server with the real
plugin binary + real Postgres via docker-compose, then asserts the live flow:

- **curl smoke (deterministic, always-pass core):**
  - fresh DB → `GET /admin/bootstrap/status` → `open:true` (count==0).
  - `POST /admin/bootstrap/redeem` wrong code → 403 `invalid_code`.
  - `POST /admin/bootstrap/redeem` correct code → 200 + session cookie; super-admin row created.
  - authenticated `POST /admin/credentials/passkey/register/begin` → 200 challenge; unauth → 401.
  - (after a credential row exists) `GET /admin/bootstrap/status` → `open:false`; re-redeem correct code → **403 `bootstrap_closed`** (V-B4 durable-close regression guard).
- **Playwright test (committed spec):** CDP **virtual authenticator** enrols a passkey post-bootstrap, logs out, logs back in via passkey (proves "set primary → subsequent login").
- **playwright-cli exploratory QA (DoD, per user):** headless isolated session manually walks the admin UI (bootstrap form → enrol → logout → passkey login → confirm bootstrap form gone), capturing screenshots. Findings recorded in the scenario `test/EXPLORATORY.md`.

## Assumptions (load-bearing)

1. Engine core steps `step.request_parse`, `step.db_query`, `step.db_exec`, `step.conditional`/`step.set`, `step.json_response`, and an `auth.jwt` session module are available in the scenario's pinned engine. *If false:* scenario app.yaml adapts to the available equivalents; plugin step unaffected.
2. Consumer can express `SELECT count(*)` of admin credentials and pass it as the step input. (True for any SQL-backed consumer; the demo proves it.)
3. CDP virtual-authenticator passkey ceremony works headless in the scenarios Playwright harness (scenario 92 precedent runs Playwright). *If false:* curl smoke still proves bootstrap+close+gating; passkey-enrol asserted at the begin-challenge level + flagged.
4. The plugin runs as a normal gRPC subprocess under the engine in docker-compose (scenario 92 precedent). *If false:* fall back to in-process registration in the scenario host.
5. `AUTH_BOOTSTRAP_CODE` delivered out-of-band by the operator (1Password/Signal/console). The step is not responsible for delivery.

## Rollback (runtime-affecting change classes)

| Change | Class | Rollback |
|---|---|---|
| plugin: new step + proto + manifest | additive code + new release tag | revert PR; do not advance the v0.3.0 tag; consumers on v0.2.12 unaffected (step simply absent). |
| registry: manifest capabilities | manifest data | revert manifest PR; `verify-capabilities` reverts to prior step set. |
| scenario: new docker-compose stack | isolated test asset | revert PR; scenario removed from `scenarios.json`; no other scenario touched. |

## Scope (this run) / Non-goals

- **In:** plugin step + contract + tests + SPEC/README/manifest → v0.3.0; registry capabilities; new workflow-scenarios admin stack (curl + Playwright + playwright-cli exploratory QA).
- **Out (tracked follow-up):** migrate gocodealone-multisite `admin_bootstrap.go` onto the step (private host; current solution works). File issue post-merge.
- **Out (Phase II, unchanged):** plugin-side JWT issuer (`auth.idp` / `step.auth_jwt_issue`); SSO is demonstrated via the existing oauth steps' pattern, passkey is the concrete primary in the demo.

## Top doubts (self-challenge, surfaced to user + accepted)

- D1 count-gate trusts consumer to wire `existing_admin_count` → **mitigated by fail-safe-closed default** (open only on explicit `0`) + demo proves wiring.
- D2 passkey ceremony in CI needs Playwright virtual authenticator (fragile) → deterministic curl smoke independently proves bootstrap+close+gating; Playwright flake can't mask a real regression.
- D3 no plugin session issuer → demo uses modular `auth.jwt` for the cookie (established consumer-owns-session pattern); plugin issuer stays Phase II.
