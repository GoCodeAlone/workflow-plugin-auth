# Durable First-Run Admin Bootstrap — Design (2026-06-02, rev 2)

Issue: GoCodeAlone/workflow-plugin-auth#23. Supersedes the http-facade framing of #23
(overtaken: gocodealone-multisite never imported the plugin; rolled bespoke
`cmd/multisite-host/admin_bootstrap.go`). Realises the "Phase II — reusable plugin
extraction" earmarked in `docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md`
(trigger = "second consumer materialises"; now fired).

> **rev 2 (adversarial cycle-1):** resolved 3 Critical + 9 Important. Session-mint
> path named to REAL engine steps (`step.m2m_token` mint + `step.auth_required`/
> `step.auth_validate` gate; bearer-token-in-body, not a cookie) — closes A2-1/A13-1/A9-1.
> Count-gate refined to **credential** count + idempotent user-seed — closes A6-1.
> db_query scalar coercion, registry backfill 0.2.7→0.3.0, virtual-authenticator
> launch-arg spike, CSRF-by-bearer, `min_code_length` dropped, scenario id=101,
> proto+CreateTypedStep wiring enumerated. Full transcript in §Cycle-1 resolutions.

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
| Engine-mediated step model; plugin is STATELESS, persistence is consumer-pipeline-owned (`step_credential.go`, `step_magic_link.go`) | New step holds NO state; takes `existing_admin_count` as INPUT (consumer supplies via `db_query`); never opens a DB/socket. |
| General-purpose, serves N consumers; per-consumer config not code deletion (SPEC C1) | Code source + super-admin identity + role label are config/env per consumer; no consumer hard-coded. |
| Strict gRPC proto contracts; manifest aligned to runtime (`wfctl plugin verify-capabilities`, SPEC C5) | Add typed `BootstrapRedeem{Config,Input,Output}` proto + STRICT_PROTO contract; wire BOTH `CreateStep` + `CreateTypedStep` + `authContractRegistry` (§Impl notes). |
| Prior design earmarked `auth.bootstrap` for v0.3.0 (2026-05-17 §Phase II) | Ship as a step in workflow-plugin-auth (NOT a new plugin, NOT an http facade). |
| Secrets never in YAML; env-sourced (magic-link `configStrOrEnv` precedent) | Code read from env (`AUTH_BOOTSTRAP_CODE` default; name overridable). YAML carries only the env-var NAME + super-admin identity. |
| Session minting is consumer-owned; engine provides the primitives (verified `mcp list_step_types`; `plugins/auth/plugin.go`) | Demo mints a bearer session JWT via `step.m2m_token` and gates routes via `step.auth_required`/`step.auth_validate` against an `auth.m2m`/`auth.jwt` provider sharing the HS256 secret. Plugin ships no JWT issuer (Phase II). |

### Home-repo determination (user asked: aligned step vs new plugin)

**Decision: a step in workflow-plugin-auth.** See `decisions/0001-bootstrap-redeem-as-stateless-count-gated-step.md`.
Bootstrap = "establish first auth identity + first credential" = an auth-credential
primitive. Composes with existing `step.auth_passkey_*` / `step.auth_oauth_*` /
`step.auth_credential_*`. The repo's own 2026-05-17 design pre-committed this.
*Rejected:* dedicated `workflow-plugin-admin-bootstrap` (fragments the auth surface);
http.Handler facade owning routes/sessions/persistence (the literal #23 ask — fights
the stateless model, no consumer needs it); operator DB-seed via SQL (needs deploy-time
DB access + no auto-close mechanism — see ADR-0001).

## §I — Interface

### New step `step.auth_bootstrap_redeem`

```
config:
  super_admin_email:  string                       # identity minted on first redeem
  super_admin_role:   string (= "super_admin")     # OUTPUT LABEL only, not a gate; role vocab is consumer-specific
  code_env:           string (= "AUTH_BOOTSTRAP_CODE")   # env var NAME holding the code
input:
  code:                 string                      # operator-submitted (from request body)
  existing_admin_count: int|int64|float64|numeric-string   # consumer supplies via db_query → step.set; coerced to int
output:
  redeemed:  bool
  email:     string                                 # set iff redeemed
  role:      string                                 # set iff redeemed
  reason:    string                                 # "" | "bootstrap_closed" | "invalid_code" | "not_configured"
  error:     string (field 100)                     # hard/internal errors only
```

`min_code_length` config knob dropped (cycle-1 A5-2 footgun); baked constant
`bootstrapMinCodeLength = 16`. `super_admin_role` kept (A5-1): an **output label** the
consumer writes to its own user row, NOT a gate (the gate is `existing_admin_count`).

**Logic (stateless, fail-safe-closed):**
1. envCode empty OR `len(envCode) < 16` → `{redeemed:false, reason:"not_configured"}`.
2. `existing_admin_count` not coercible to int, OR not exactly `0` (missing / non-numeric / negative / >0) → `{redeemed:false, reason:"bootstrap_closed"}`. **Default-deny.** Coercion accepts `int`/`int64`/`float64` (the JSON-number wire type from `db_query`/`step.set`) / numeric `string`; else deny.
3. count `==0` AND `constantTimeEqual(code, envCode)` → `{redeemed:true, email, role}`.
4. count `==0` AND mismatch → `{redeemed:false, reason:"invalid_code"}`.

`constantTimeEqual` = length-guard + `subtle.ConstantTimeCompare` (mirrors multisite `admin_bootstrap.go:213`).

### Core invariant (the design's headline)

> **Bootstrap is OPEN ⟺ zero admin CREDENTIALS exist.**

Gate counts **credential rows** (kind ∈ {passkey,google,facebook}), NOT user rows. So:
fresh DB → 0 credentials → open; redeem creates the super-admin USER row but no
credential → still open (operator needs the session to enrol); enrol passkey/SSO →
1 credential → **closed**; redeploy w/ same DB → stays closed; empty store → re-opens
(break-glass). Beats multisite's never-closing secret AND a one-shot token (which
can't recover from credential loss).

### Consumer wiring (demonstrated in the scenario, NOT shipped in the plugin)

```
POST /admin/bootstrap/redeem  (JSON body {code}; bearer-token response → no cookie, no CSRF surface):
  step.request_parse (parse_body)                              → .body.code
  step.db_query count_creds (mode: single)
      SELECT count(*) AS n FROM credentials WHERE kind IN ('passkey','google','facebook')
                                                               → .row.n
  step.set existing_admin_count: "{{ .steps.count_creds.row.n }}"
  step.auth_bootstrap_redeem {code: .body.code, existing_admin_count}
  step.conditional .redeemed:
    true:
      step.db_exec INSERT users(email,role) VALUES(...) ON CONFLICT(email) DO NOTHING   # idempotent seed
      step.m2m_token (generate) claims {sub: email, roles:[role]}  → .token             # signed w/ shared HS256 secret
      step.json_response 200 {token, redirect:"/admin/credentials/passkey/register/begin"}
    false → step.json_response 403 {reason}

Authenticated routes (e.g. POST /admin/credentials/passkey/register/{begin,finish}):
  step.auth_required  (validates Bearer JWT against auth.m2m/auth.jwt provider; 401 if absent/invalid)
  → existing step.auth_passkey_* ; passkey FINISH writes the credential row → count→1 → bootstrap closes.
```
SSO-as-primary is the same shape via `step.auth_oauth_*` then a credential INSERT.
Concurrent pre-enrolment redeems are harmless: same principal, `ON CONFLICT DO NOTHING`
converges to one super-admin row; the window closes the instant the first credential lands.

## §V — Invariants (backport to SPEC.md)

- V-B1: redeem succeeds only when `existing_admin_count == 0`; any other/uncoercible value → denied (default-deny).
- V-B2: code compared constant-time; configured code `< 16` chars → `not_configured` (never matches).
- V-B3: plugin step writes no state; never opens a DB/socket; identity persistence + session minting are consumer-owned.
- V-B4: once ≥1 admin **credential** exists, no code value re-opens bootstrap (durable close).
- V-B5: redeem output/logs never echo the configured code or env value.
- V-B6: the gate counts CREDENTIAL rows, not user rows — the super-admin user may exist with no credential while bootstrap is still open (the enrolment window).

## Security Review

- **AuthZ/authn:** code is the sole secret; gate is the `count==0` precondition. Leaked code is INERT once a credential exists (V-B4). Constant-time compare + length guard. Default-deny on ambiguous/uncoercible count.
- **CSRF:** demo returns the session as a **bearer token in the JSON body** (client sends `Authorization: Bearer`), so there is no ambient-cookie auth and no CSRF surface on the redeem route. A consumer that prefers a cookie MUST set `SameSite=Strict` + JSON-only `Content-Type` on the redeem route (documented).
- **Brute force:** only possible in the pre-first-credential window. Mitigations: ≥16-char code (constant-enforced), constant-time compare, consumer SHOULD rate-limit the redeem route (documented). Window is short and closes permanently on first enrolment — strictly better than multisite's forever-open secret.
- **Secrets/logging:** code from env only; `os.Getenv` at request time (rotation = change env + restart); never logged; never in output (V-B5). Security relies on the env var being secret at the infra level (distroless containers, no metadata-endpoint `/proc` exposure).
- **Concurrent redeem:** §I — idempotent user-seed + credential-count gate make it harmless.
- **Least privilege / deps:** minted role exactly `super_admin` (config label); no new external deps (stdlib `crypto/subtle`); STRICT_PROTO contract like every sibling step.

## Infrastructure Impact

- **Plugin:** additive step + proto message + manifest entries. New tag **v0.3.0** (minor: additive step). `minEngineVersion` unchanged (0.57.2; same SDK surface). `version`/`downloads` stay version-discipline placeholders (release workflow templates them). Pre-tag check: `git ls-remote --tags origin | grep v0.3.0` must be empty (A8-2).
- **Registry:** manifest is **stale at v0.2.7 (25 steps)**; current `plugin.json` has 29. The registry PR MUST rebuild to **v0.3.0 with all 30** (29 current + bootstrap) so `verify-capabilities` matches runtime (A8-1). Update `manifest.json` + `v1/index.json`; confirm `minEngineVersion` consistent with `plugin.json` (0.57.2).
- **Scenario:** new isolated docker-compose stack (engine + plugin gRPC subprocess + `postgres:16-alpine`); engine uses a `database.workflow` module (`{driver: postgres, dsn: ...}`) bound by `step.db_query`/`step.db_exec`; own scenario port `:18101`; no shared-state impact, no cloud.
- **Migrations:** none in the plugin. Scenario seed creates scenario-local `users` + `credentials` tables.
- **Deploy/rollback:** §Rollback. No prod approval (public plugin + test scenario).

## Multi-Component Validation

Real boundaries, no mock-only proof: **engine ↔ plugin (gRPC) ↔ Postgres (`database.workflow`) ↔ HTTP**.
Scenario `101-auth-admin-bootstrap` boots the real workflow server + real plugin binary +
real Postgres via docker-compose, then asserts the live flow:

- **curl smoke (deterministic, always-pass core):**
  - fresh DB → `GET /admin/bootstrap/status` → `open:true` (count==0).
  - `POST /admin/bootstrap/redeem` wrong code → 403 `invalid_code`.
  - correct code → 200 + **bearer token in body**; super-admin user row created.
  - authenticated (Bearer) `POST /admin/credentials/passkey/register/begin` → 200 challenge; no/invalid Bearer → 401 (proves `step.auth_required` gate, server-side).
  - after a credential row exists → `GET /admin/bootstrap/status` → `open:false`; re-redeem correct code → **403 `bootstrap_closed`** (V-B4 regression guard).
- **Playwright test (committed spec):** CDP **virtual authenticator** enrols a passkey post-bootstrap, logs out, logs back in via passkey (proves "set primary → subsequent login"). Requires `chromium.launch(args:['--enable-blink-features=WebAuthenticationTesting'])` — added to the scenario's Playwright project config; pre-impl spike confirms headless support, else fall back to asserting at the passkey-begin challenge level + documenting the limitation (A2-2).
- **playwright-cli exploratory QA (DoD, per user):** sequence = run `seed.sh` (stack up) → `playwright-cli` headless isolated session at `http://127.0.0.1:18101` walks bootstrap form → enrol → logout → passkey login → confirm bootstrap form gone, capturing screenshots → `docker compose down`. Findings recorded in `scenarios/101-auth-admin-bootstrap/test/EXPLORATORY.md` (A12-1 sequencing).

## §Implementation notes (carry into plan; cycle-1 A3-1)

Wiring `step.auth_bootstrap_redeem` end-to-end requires ALL of:
1. add `BootstrapRedeemConfig`/`BootstrapRedeemInput`/`BootstrapRedeemOutput` to `internal/contracts/auth.proto`;
2. regenerate `auth.pb.go` (resolve regen: no Makefile target — check for `buf.gen.yaml`/script or invoke `protoc` matching the existing header);
3. add case to `CreateStep` (map mode);
4. add case to `CreateTypedStep` (`sdk.NewTypedStepFactory`, typed mode);
5. add `stepContract("step.auth_bootstrap_redeem", "BootstrapRedeemConfig","BootstrapRedeemInput","BootstrapRedeemOutput")` to `authContractRegistry`;
6. add to `allStepTypes` (`internal/plugin.go`) + `plugin.json` stepTypes + capabilities.stepTypes.
Missing any one → `verify-capabilities` STRICT_PROTO mismatch at runtime (C5).

## Assumptions (load-bearing)

1. Engine steps `step.request_parse`, `step.db_query`, `step.db_exec`, `step.conditional`/`step.set`, `step.json_response`, `step.m2m_token`, `step.auth_required`/`step.auth_validate`, and modules `database.workflow` + `auth.m2m`/`auth.jwt` exist in the pinned engine — **verified** via `mcp list_step_types` (164 steps) + `plugins/auth/plugin.go` + `plugins/storage/plugin.go`.
2. Consumer can `SELECT count(*)` of admin credentials and pass it (coerced) as the step input — proven by the demo.
3. CDP virtual-authenticator passkey ceremony works headless with `--enable-blink-features=WebAuthenticationTesting` (scenario 92 runs Playwright but NOT a virtual authenticator — unproven here → pre-impl spike + fallback, A2-2).
4. Plugin runs as a gRPC subprocess under the engine in docker-compose (scenario 92 precedent). *If false:* in-process registration fallback.
5. `AUTH_BOOTSTRAP_CODE` delivered out-of-band by the operator. Step not responsible for delivery.
6. `step.m2m_token` mint + `step.auth_required` validate share the HS256 secret via co-configured `auth.m2m`/`auth.jwt` modules — to be confirmed by a plan-phase wiring spike before the scenario locks.

## Rollback (runtime-affecting change classes)

| Change | Class | Rollback |
|---|---|---|
| plugin: new step + proto + manifest | additive code + new release tag | revert PR; do not advance v0.3.0 tag; consumers on v0.2.12 unaffected (step absent). |
| registry: manifest v0.2.7→v0.3.0 (30 steps) | manifest data | revert manifest PR; `verify-capabilities` reverts to prior set. |
| scenario: new docker-compose stack | isolated test asset | revert PR; remove from `scenarios.json`; no other scenario touched. |

## Scope (this run) / Non-goals

- **In:** plugin step + contract + tests + SPEC/README/manifest → v0.3.0; registry capabilities rebuild; new workflow-scenarios admin stack (curl + Playwright + playwright-cli exploratory QA).
- **Out (tracked follow-up):** migrate gocodealone-multisite `admin_bootstrap.go` onto the step (private host; current solution works). File issue post-merge.
- **Out (Phase II):** plugin-side JWT issuer (`auth.idp` / `step.auth_jwt_issue`); SSO demonstrated via existing oauth-step pattern, passkey is the concrete primary in the demo.

## Cycle-1 resolutions (adversarial-design-review --phase=design)

| id | sev | finding | resolution |
|---|---|---|---|
| A2-1 / A13-1 | Critical | no pipeline step mints a session | named REAL steps: `step.m2m_token` mint + `step.auth_required`/`auth_validate` gate; bearer-in-body |
| A6-1 | Critical | count-gate TOCTOU; `ON CONFLICT` insufficient | gate on **credential** count (not users); user-seed idempotent by email; pre-enrolment concurrent redeems harmless (same principal); close on first credential |
| A3-1 | Important | CreateTypedStep + contractRegistry wiring not enumerated | §Implementation notes lists all 6 wiring points |
| A4-1 | Important | no docker-compose+Postgres precedent; DB module unnamed | engine module `database.workflow` `{driver:postgres,dsn}` named |
| A6-2 | Important | restart mid-redeem | documented: session lost, bootstrap stays open (count still 0) → redeem again; no data loss |
| A6-3 / A13-3 | Important | `db_query` scalar → float64 not int32 | step coerces int/int64/float64/numeric-string; `mode:single` + `.row.n` + `step.set`; unit test for float64(0) |
| A7-1 | Important | CSRF on redeem route | bearer-token-in-body (no ambient cookie); cookie path documents SameSite=Strict |
| A8-1 | Important | registry manifest stale (0.2.7/25 steps) | rebuild to v0.3.0 with all 30 steps + index.json |
| A9-1 | Important | e2e boundary incomplete w/o session step | resolved by A2-1; smoke proves gate server-side |
| A13-2 | Important | registry manifest pre-edit existence check | confirmed exists at v0.2.7; plan notes current version |
| A2-2 | Important | virtual authenticator headless unproven | launch-arg + pre-impl spike + begin-challenge fallback |
| A5-1 | Minor | `super_admin_role` knob | kept as output label (not a gate); documented |
| A5-2 | Minor | `min_code_length` knob | dropped; baked constant 16 |
| A7-2 | Minor | env-secret exposure | acknowledged in §Security |
| A8-2 | Minor | tag pre-existence check | `git ls-remote --tags` in plan |
| A11-1 | Minor | operator-DB-seed alternative | added to ADR-0001 rejected list |
| A12-1 | Minor | playwright-cli sequencing | seed-first sequence documented |
| A4-2 | Minor | scenario id placeholder | fixed to 101 |

## Top doubts (self-challenge, accepted)

- D1 count-gate trusts consumer wiring → fail-safe-closed default + demo proves wiring.
- D2 passkey ceremony in CI needs virtual authenticator (fragile) → deterministic curl smoke independently proves bootstrap+close+gating.
- D3 no plugin session issuer → demo uses engine `step.m2m_token`/`auth.m2m` (consumer-owns-session pattern); plugin issuer stays Phase II.
