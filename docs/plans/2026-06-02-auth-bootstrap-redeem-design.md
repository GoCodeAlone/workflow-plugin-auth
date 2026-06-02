# Durable First-Run Admin Bootstrap — Design (2026-06-02, rev 3)

Issue: GoCodeAlone/workflow-plugin-auth#23. Supersedes the http-facade framing of #23
(overtaken: gocodealone-multisite never imported the plugin; rolled bespoke
`cmd/multisite-host/admin_bootstrap.go`). Realises (and extends) the "Phase II"
earmark in `docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md`.

> **rev 3 (adversarial cycle-2):** cycle-1 wrongly named `step.m2m_token`/`step.auth_required`
> as the session layer — both are **schema-only types with NO runtime factory** (verified
> by grepping every `StepFactories()` in the engine; `mcp list_step_types` lists schema
> types, not runtime steps). The only real runtime steps are `step.auth_validate` (gate) +
> `step.token_revoke` (logout); minting exists only inside `auth.jwt`/`auth.m2m` HTTP
> handlers, never as a pipeline step. **Resolution:** ship a minimal **`step.auth_jwt_issue`**
> (HS256 mint) alongside `step.auth_bootstrap_redeem` so the flow is 100% real runtime.
> Also: specify the `GET /admin/bootstrap/status` pipeline, fix the gate wiring
> (`step.auth_validate` needs `auth_module`+`token_source`), document token-expiry /
> passkey-FINISH-fail / token-storage, registry now 31 steps. Transcript in §Cycle-2.
>
> **rev 2 (cycle-1):** resolved 3C+9I (count-gate→credential count, db_query int coercion,
> CSRF-by-bearer, registry backfill, min_code_length dropped, scenario id=101). See §Cycle-1.

## §G — Goal

Reusable, durable first-run admin login: fresh deploy → operator redeems an
out-of-band seeded code → super-admin session → enrols **passkey** (or links **SSO**)
as PRIMARY credential → bootstrap path **auto-closes**. Durable across
restarts/redeploys; re-opens only when the credential store is empty (break-glass).
Replaces the multisite anti-pattern (permanent reusable shared secret → stateless JWT,
no upgrade path, no persistence — incl. its bespoke `auth.Service.GenerateToken` mint).
Prove end-to-end in a workflow-scenarios admin stack.

## §C — Constraints / Global Design Guidance

Guidance: none found (`docs/design-guidance.md` absent in repo/workspace/engine);
durable constraints captured here from SPEC.md + prior design docs + user Q&A.

| guidance (source) | design response |
|---|---|
| Engine-mediated step model; plugin is STATELESS; persistence consumer-owned (`step_credential.go`, `step_magic_link.go`) | Both new steps hold NO state. `bootstrap_redeem` takes `existing_admin_count` as INPUT; `auth_jwt_issue` is a pure crypto transform (subject+claims → signed token). Neither opens a DB/socket. |
| General-purpose, N consumers; per-consumer config not code deletion (SPEC C1) | Code, super-admin identity, role label, signing-secret env-name are all config/env; no consumer hard-coded. |
| Strict gRPC proto contracts; manifest = runtime (`verify-capabilities`, SPEC C5) | Both steps get typed proto + STRICT_PROTO contract; wire `CreateStep`+`CreateTypedStep`+`authContractRegistry`+`allStepTypes`+`plugin.json` (§Impl notes). |
| Prior design earmarked bootstrap + JWT-issue for Phase II (2026-05-17 §Phase II) | Ship the MINIMAL slice now (count-gated redeem + HS256 symmetric issue); full IDP (JWKS, refresh, asymmetric, `auth.idp` module) stays Phase II. See ADR-0002. |
| Secrets never in YAML; env-sourced (`configStrOrEnv` precedent) | Bootstrap code from `AUTH_BOOTSTRAP_CODE`; signing secret from `AUTH_JWT_SECRET` (names overridable). YAML carries only env-var NAMES + identity. |
| Session minting was bespoke per-consumer (BMW `step.bmw.generate_token`, multisite `auth.Service.GenerateToken`) | `step.auth_jwt_issue` is the portable replacement, validated by the engine's existing `step.auth_validate` against an `auth.jwt` module sharing the secret. |

### Home-repo determination

**A step in workflow-plugin-auth** (see ADR-0001). Bootstrap + session-issue are
auth-credential primitives composing with existing passkey/oauth/credential steps. The
2026-05-17 design pre-committed both. *Rejected:* new `workflow-plugin-admin-bootstrap`
plugin; http.Handler facade owning routes/sessions/persistence; operator SQL-seed (ADR-0001 alt-d).

## §I — Interface

### New step 1 — `step.auth_bootstrap_redeem`

```
config:
  super_admin_email: string                          # identity minted on first redeem
  super_admin_role:  string (= "super_admin")        # OUTPUT LABEL only, not a gate
  code_env:          string (= "AUTH_BOOTSTRAP_CODE") # env var NAME holding the code
input:
  code:                 string
  existing_admin_count: int|int64|float64|numeric-string   # via db_query → step.set; coerced to int
output:
  redeemed: bool ; email: string ; role: string
  reason:   string  # "" | "bootstrap_closed" | "invalid_code" | "not_configured"
  error:    string (field 100)
```
Logic (stateless, fail-safe-closed): (1) envCode empty OR `len<16` → `not_configured`.
(2) count not coercible to int OR not exactly `0` → `bootstrap_closed` (**default-deny**;
coercion accepts int/int64/float64/numeric-string). (3) count`==0` + `constantTimeEqual`
→ `redeemed:true`. (4) count`==0` + mismatch → `invalid_code`. `bootstrapMinCodeLength=16`
baked constant (cycle-1 A5-2). `super_admin_role` is an output label (cycle-1 A5-1).

### New step 2 — `step.auth_jwt_issue` (the minting primitive; cycle-2 C2-1 fix)

```
config:
  secret_env:  string (= "AUTH_JWT_SECRET")   # env var NAME holding the HS256 secret
  issuer:      string (= "workflow-plugin-auth")
  ttl_seconds: int    (= 3600)                # generous bootstrap-session TTL (cycle-2 I2-4)
input:
  subject: string                              # → "sub" claim
  claims:  map<string,any>                     # extra claims, e.g. {roles:["super_admin"], email:...}
output:
  token: string ; expires_at: string(RFC3339) ; error: string (field 100)
```
HS256 sign via `github.com/golang-jwt/jwt/v5` (promoted to direct dep; already in the
module graph). Emits standard claims `sub,iat,exp,iss,jti` + caller claims. Secret `<16`
chars OR empty → `{error:"signing secret not configured"}`. **Verified compatible** with
the engine gate: `JWTAuthModule.Authenticate` (`module/jwt_auth.go:131`) is signature-only
HS256 (no user-store dependency) + optional blacklist → a token signed with the shared
secret validates. Minimal by design: no JWKS / refresh / asymmetric (Phase II, ADR-0002).

### Status read — `GET /admin/bootstrap/status` pipeline (cycle-2 I2-3; consumer-owned)

```
step.db_query count_creds (mode: single): SELECT count(*) AS n FROM credentials WHERE kind IN ('passkey','google','facebook')  → .row.n
step.json_response 200 { open: {{ eq (.steps.count_creds.row.n) 0 }} , credential_count: .row.n }
```
Lets the login UI render the bootstrap form (open) vs passkey/SSO buttons (closed). Pure
consumer wiring (no plugin primitive — honours V-B3).

### Core invariant (headline)

> **Bootstrap is OPEN ⟺ zero admin CREDENTIALS exist** (kind ∈ {passkey,google,facebook}).

Counts credential rows, NOT users. Fresh DB → open; redeem creates the super-admin USER
(no credential) → still open (operator needs the session to enrol); enrol passkey/SSO →
1 credential → **closed**; redeploy same DB → stays closed; empty store → re-opens (break-glass).

### Consumer wiring (demonstrated in the scenario; verified against real runtime steps)

```
POST /admin/bootstrap/redeem  (JSON {code}; bearer-token response → no cookie, no CSRF surface):
  step.request_parse(parse_body)                                          → .body.code
  step.db_query count_creds(mode:single) SELECT count(*) AS n ...         → .row.n
  step.set existing_admin_count: "{{ .steps.count_creds.row.n }}"
  step.auth_bootstrap_redeem {code:.body.code, existing_admin_count}
  step.conditional .redeemed:
    true:
      step.db_exec INSERT users(email,role) VALUES(...) ON CONFLICT(email) DO NOTHING   # idempotent seed
      step.auth_jwt_issue {subject:.email, claims:{roles:[.role], email:.email}}        → .token  (HS256, AUTH_JWT_SECRET)
      step.json_response 200 {token, redirect:"/admin/credentials/passkey/register/begin"}
    false → step.json_response 403 {reason}

Protected routes — POST /admin/credentials/passkey/register/{begin,finish}, /admin/logout:
  step.auth_validate {auth_module: jwtauth, token_source: ".headers.Authorization"}     # REAL gate; 401 if absent/invalid
  → existing step.auth_passkey_* ; FINISH writes credential row → count→1 → bootstrap closes
  logout: step.token_revoke (real)

Passkey login — POST /admin/login/passkey/{begin,finish}:
  step.auth_passkey_begin_login / finish_login (validate) → step.auth_jwt_issue → {token}
```
Modules: `auth.jwt` (name `jwtauth`, `secret` from `AUTH_JWT_SECRET`, `tokenExpiry:1h`) is
the AuthProvider the gate validates against; `database.workflow` (`{driver:postgres,dsn}`)
backs db_query/db_exec. Concurrent pre-enrolment redeems are harmless (same principal,
`ON CONFLICT DO NOTHING`; window closes on first credential).

## §V — Invariants (backport to SPEC.md)

- V-B1: redeem succeeds only when `existing_admin_count == 0`; any other/uncoercible value → denied.
- V-B2: code constant-time compared; configured code `<16` chars → `not_configured`.
- V-B3: plugin steps write no state, open no DB/socket; persistence + routing are consumer-owned.
- V-B4: once ≥1 admin **credential** exists, no code value re-opens bootstrap (durable close).
- V-B5: redeem/issue output + logs never echo the code, env secret, or signing key.
- V-B6: gate counts CREDENTIAL rows, not user rows (the super-admin user may exist with no credential during the enrolment window).
- V-B7: `auth_jwt_issue` signs HS256 only when the configured secret is ≥16 chars; else returns an error (no unsigned/empty-secret token).

## Security Review

- **AuthZ/authn:** code is the sole bootstrap secret; gate is `count==0`. Leaked code INERT once a credential exists (V-B4). Constant-time compare + length guard. Default-deny on ambiguous count.
- **CSRF:** demo returns the session as a **bearer token in the JSON body** (client sends `Authorization: Bearer`) → no ambient-cookie auth, no CSRF surface. A consumer choosing cookies MUST set `SameSite=Strict` + JSON-only redeem route (documented).
- **Brute force:** possible only in the pre-first-credential window. Consumer guidance (explicit, cycle-2 M2-2): **put the redeem route behind `step.rate_limit`** (engine step) — e.g. 5/min/IP — and use a ≥24-char code; the window closes permanently on first enrolment (strictly better than multisite's forever-open secret).
- **Token storage (cycle-2 I2-5):** demo admin UI keeps the bearer in an in-memory JS variable / `sessionStorage` (the Playwright spec reuses it across steps); **production consumers MUST prefer short-lived tokens + HttpOnly cookies** (documented in the scenario README). `auth_jwt_issue` sets `jti` so `step.token_revoke` can blacklist on logout.
- **Secrets/logging:** code + signing secret from env; never logged; never in output (V-B5, V-B7). Rotation = change env + restart. Relies on env secrecy at the infra layer.
- **Least privilege / deps:** minted role exactly `super_admin` (config label); new direct dep `golang-jwt/jwt/v5` (already in graph, BSD-3, widely used). STRICT_PROTO contracts.

## Infrastructure Impact

- **Plugin:** 2 additive steps + 2 proto message-sets + manifest entries. New tag **v0.3.0** (minor: additive). `minEngineVersion` unchanged (0.57.2). `version`/`downloads` stay discipline placeholders. Pre-tag: `git ls-remote --tags origin | grep v0.3.0` empty (A8-2).
- **Registry:** manifest stale at v0.2.7 (25 steps); current `plugin.json` 29. Rebuild to **v0.3.0 with all 31** (29 + bootstrap_redeem + auth_jwt_issue); update `manifest.json` + `v1/index.json`; align `minEngineVersion` to 0.57.2 (A8-1).
- **Scenario:** isolated docker-compose (engine + plugin gRPC subprocess + `postgres:16-alpine` + `auth.jwt` module); engine port `:18101`; no shared state, no cloud.
- **Migrations:** none in plugin. Scenario seed creates scenario-local `users` + `credentials` tables.
- **Rollback:** §Rollback. No prod approval.

## Multi-Component Validation

Real boundaries: **engine ↔ plugin (gRPC) ↔ Postgres (`database.workflow`) ↔ HTTP**, all
steps verified to have runtime factories. Scenario `101-auth-admin-bootstrap`:

- **curl smoke (deterministic core):** fresh DB → `GET /admin/bootstrap/status` `open:true`; redeem wrong code → 403 `invalid_code`; correct code → 200 + bearer token (super-admin row created); authenticated `POST .../passkey/register/begin` → 200 challenge, no/invalid Bearer → **401** (proves `step.auth_validate` server-side gate); after credential exists → status `open:false` + re-redeem → **403 `bootstrap_closed`** (V-B4 guard).
- **Playwright test (committed):** CDP **virtual authenticator** enrols a passkey post-bootstrap, logs out (`token_revoke`), logs back in via passkey. Needs `chromium.launch(args:['--enable-blink-features=WebAuthenticationTesting'])`; pre-impl spike confirms headless support else fall back to begin-challenge assertion + documented limitation (A2-2).
- **playwright-cli exploratory QA (DoD):** seq = `seed.sh` up → `playwright-cli` headless isolated session at `http://127.0.0.1:18101`: bootstrap form → enrol → logout → passkey login → confirm bootstrap form gone; screenshots → `test/EXPLORATORY.md` → `docker compose down`.

## §Implementation notes (carry into plan)

Each new step requires ALL of (cycle-1 A3-1): (1) proto messages in `internal/contracts/auth.proto`;
(2) regen `auth.pb.go` via **bare `protoc`** (no Makefile target, no `buf.gen.yaml`; header shows
`protoc-gen-go v1.36.11`): `protoc --go_out=. --go_opt=paths=source_relative internal/contracts/auth.proto`
(cycle-2 M2-3); (3) `CreateStep` case; (4) `CreateTypedStep` case (`sdk.NewTypedStepFactory`);
(5) `stepContract(...)` in `authContractRegistry`; (6) add to `allStepTypes` + `plugin.json`
stepTypes + capabilities.stepTypes. `go.mod`: promote `golang-jwt/jwt/v5` to direct require.

## Assumptions (load-bearing; verified)

1. Engine steps `step.request_parse`, `step.db_query`, `step.db_exec`, `step.conditional`/`step.set`, `step.json_response`, `step.auth_validate`, `step.token_revoke`, `step.rate_limit` and modules `database.workflow` + `auth.jwt` have **runtime factories** — VERIFIED by grepping `StepFactories()`/`ModuleFactories()` (not just `mcp list_step_types`, which lists schema-only types like `step.m2m_token`/`step.auth_required` that DON'T execute — the cycle-1 trap).
2. `auth.jwt.Authenticate` is signature-only HS256 (`module/jwt_auth.go:131`) → an `auth_jwt_issue`-minted token (same `AUTH_JWT_SECRET`) validates without a user-store entry — VERIFIED.
3. Consumer can `SELECT count(*)` of admin credentials and pass it coerced as input — proven by the demo.
4. CDP virtual authenticator works headless with the launch flag — UNPROVEN here (scenario 92 runs Playwright but no virtual authenticator) → pre-impl spike + begin-challenge fallback (A2-2).
5. Plugin runs as a gRPC subprocess under the engine in docker-compose (scenario 92 precedent). *If false:* in-process registration fallback.
6. `AUTH_BOOTSTRAP_CODE` + `AUTH_JWT_SECRET` delivered out-of-band by the operator.

## Rollback (runtime-affecting change classes)

| Change | Class | Rollback |
|---|---|---|
| plugin: 2 steps + proto + manifest | additive code + new tag | revert PR; don't advance v0.3.0; consumers on v0.2.12 unaffected (steps absent). |
| registry: v0.2.7→v0.3.0 (31 steps) | manifest data | revert manifest PR; `verify-capabilities` reverts. |
| scenario: docker-compose stack | isolated test asset | revert PR; remove from `scenarios.json`. |

## Scope / Non-goals

- **In:** plugin steps `auth_bootstrap_redeem` + `auth_jwt_issue` + contracts + tests + SPEC/README/manifest → v0.3.0; registry rebuild; new scenario 101 (curl + Playwright + playwright-cli QA).
- **Out (tracked follow-up):** migrate gocodealone-multisite onto the steps (private host; current solution works). File issue post-merge.
- **Out (Phase II, ADR-0002):** full IDP — JWKS endpoint, refresh tokens, asymmetric/ES256, `auth.idp` module, key rotation. The minimal HS256 symmetric `auth_jwt_issue` ships now.

## Cycle-2 resolutions (adversarial-design-review --phase=design)

| id | sev | finding | resolution |
|---|---|---|---|
| C2-1 / C2-3 | Critical | `step.m2m_token` has no runtime factory → minting fictional | ship real `step.auth_jwt_issue` (HS256); verified `auth.jwt.Authenticate` accepts it |
| C2-2 | Critical | `step.auth_required` has no runtime factory | use real `step.auth_validate` (gate) + `step.token_revoke` (logout) |
| I2-1 | Important | minting path unresolved | `auth_jwt_issue` is the in-plugin mint; no reliance on unexported `issueToken` |
| I2-2 | Important | gate wiring wrong (name + missing config) | wiring uses `step.auth_validate {auth_module, token_source}` |
| I2-3 | Important | `GET /admin/bootstrap/status` unspecified | added §I pipeline (db_query count → json_response) |
| I2-4 | Important | m2m token expiry vs enrolment | `auth.jwt tokenExpiry:1h` + `auth_jwt_issue ttl_seconds:3600`; documented re-redeem |
| I2-5 | Important | bearer token storage unspecified | demo in-memory/sessionStorage; prod HttpOnly-cookie guidance; `jti`+`token_revoke` |
| M2-1 | Minor | passkey FINISH fail leaves bootstrap open | documented (correct: count still 0 → re-redeem; no retry logic needed) |
| M2-2 | Minor | rate-limit was self-referential | explicit `step.rate_limit` guidance sentence in §Security |
| M2-3 | Minor | proto regen tool | bare `protoc` + version pinned in §Impl notes |

## Cycle-1 resolutions (summary)

count-gate→**credential** count + idempotent user-seed (A6-1); db_query int coercion (A6-3/A13-3);
CSRF-by-bearer (A7-1); registry backfill (A8-1); `min_code_length` dropped (A5-2); `super_admin_role`
kept as output label (A5-1); scenario id=101 (A4-2); restart-mid-redeem documented (A6-2); tag pre-check (A8-2);
operator-DB-seed added to ADR-0001 (A11-1); playwright-cli seed-first sequencing (A12-1).

## Top doubts (self-challenge, accepted)

- D1 count-gate trusts consumer wiring → fail-safe-closed default + demo proves wiring.
- D2 passkey ceremony in CI needs virtual authenticator (fragile) → deterministic curl smoke independently proves bootstrap+close+gating.
- D3 `auth_jwt_issue` is HS256-only → sufficient for the demo + symmetric consumers; asymmetric/JWKS/refresh deferred to Phase II (ADR-0002), not silently dropped.
