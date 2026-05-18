# Admin Bootstrap + Passkey Upgrade — Design (2026-05-17, rev 9)

> **Rev-9 amendment (plan-phase adversarial cycle 11):** Rewrote PR-2 step 3 (bootstrap-link), step 4 (bootstrap-redeem), and step 6 (runbook curl example) to match the plan's actual rev-11 implementation: publicly-reachable endpoint (not localhost-bound), GET redeem with email+token query params (not POST + body), TCP curl (not Unix socket), URL in response body (not log), NEW `/api/v1/auth/admin/enrol-passkey/*` pipelines (not modifying existing routes), session JWT reads role from DB (not hardcoded), 24h expiry in config block, SQL-side expires_at filter, case-insensitive email lookup, mark_used as `step.db_query mode: single` for `.found` semantics. The rev-8 amendment header claimed scrub-throughout; design body sections 3/4/6 were missed in that cycle.
>
> **Rev-8 amendment (plan-phase adversarial cycle 10):** Scrubbed Top Doubts row, Goal §2, allowlist-miss row, and Assumption #2. Corrected hash_password + verify_password call-site counts to 2 each. Bootstrap-link response: URL-on-hit (200) vs not_eligible (404). Rate-limit rules engine no-op documented.
>
> **Rev-7 amendment (cycle-9 cross-doc fix):** Corrected hash_password (`:881` + `:11116`) and verify_password (`:1073` + `:9447`) call-site counts to 2 each.
>
> **Rev-6 amendment (plan-phase adversarial cycle 5):** Dropped the "localhost-bound" claim throughout. BMW's http.server binds `:8080` on all interfaces (verified `app.yaml:248`) and is fronted by Tailscale serving `:443` to the tailnet. Bearer token is the SOLE protection. Defence-in-depth strengthened by (a) ≥32-char `BOOTSTRAP_OPERATOR_TOKEN` enforced via deploy precondition, (b) rate-limit rules added to existing middleware for `/admin/bootstrap-*`. Plan rev 6 also fixes a "first-redeem-wins" vs "newest-mint-wins" semantic drift by invalidating prior unredeemed admin_bootstrap tokens before each new mint.
>
> **Rev-5 amendment (from plan-phase adversarial cycle 3):** URL is returned in the `POST /admin/bootstrap-link` response body. Redeem endpoint is GET (browser-clickable; matches existing `/auth/magic-link?token=...` pattern). Timing-oracle leak accepted given bearer-token gate.


> **Revision history:** rev 1 → rev 2 → rev 3 → rev 4 (this doc) following three adversarial-design-review FAIL cycles. Skill cap (2 revisions before user escalation) reached at rev 3; rev 4 applies cycle-3 mechanical fact-fixes per autonomous-mode mandate (user granted blanket autonomy for brainstorm/design/implementation). Cycle-3 findings resolved mechanically (no structural change beyond dropping PR-3 hash migration and switching bootstrap-redeem to POST):
>
> | Cycle-3 Critical | Rev-4 resolution |
> |---|---|
> | bcrypt cost regression (plugin uses `DefaultCost`=10, bespoke uses 12) | **Drop PR-3 hash_password swap.** Keep bespoke `step.bmw.hash_password`. Only verify_password is swapped (cost-agnostic; verify reads cost from hash itself). Phase II adds cost-configurable hash step in plugin v0.2.5+. |
> | `step.auth_magic_link_generate` ignores `expiry_minutes` (hardcoded 15) | Use 15-minute expiry. Doc corrected. |
> | Role schema misquoted | Corrected to actual: `'user', 'admin', 'super_admin', 'moderator', 'support'` (per `migrations/20260308000001_add_rbac_permissions.up.sql:63`). |
> | `step.bmw.generate_token` call-site count | Corrected to 9 (verified `grep -c`). Bootstrap-redeem adds site #10. |
> | Allowlist branching not timing-safe | Accepted: endpoint is operator-only behind bearer token (≥32-char min-entropy); leak surface is low because only the operator can probe. Note added; not mitigated. |
>
> Earlier history: rev 3 dropped all plugin work (YAGNI). Rev 2 dropped HKDF/new module/new migration in favour of magic-link reuse. Rev 1 was the original.

## Goal

1. Restore BuyMyWishlist (BMW) **signup AND login** (both currently HTTP 500). Root cause is suspected to be plugin-engine handshake failure (BMW pins workflow v0.20.1; existing in-use auth-plugin pipelines target v0.51.6-era strict-proto contracts), with template nil-derefs as secondary fragility surface. Both addressed.
2. Stand up an **admin bootstrap login flow** for BMW operator (`codingsloth@pm.me`): operator triggers magic-link mint via a bearer-token-gated BMW endpoint → URL → user redeems → JWT session → enrols passkey via existing passkey routes → subsequent logins use passkey; bootstrap is break-glass only.
3. Migrate ONE of BMW's two password-related bespoke steps onto its plugin equivalent (`step.bmw.verify_password` → `step.auth_password_verify`). **Keep** `step.bmw.hash_password` because the plugin's `step.auth_password_hash` uses `bcrypt.DefaultCost` (10) vs the bespoke cost=12 — silent security downgrade would result. Phase II opens a small plugin PR (v0.2.5) adding configurable `cost` field, then BMW can swap. Bespoke `step.bmw.generate_token` retained (9 existing + 1 new call site in bootstrap-redeem = 10 total; no plugin replacement exists today).
4. Document a forward path for cross-product SSO (issuer, JWKS endpoint, refresh tokens, JWT issue/verify) and plugin extraction of the bootstrap pattern as **Phase II**, triggered when a second consumer materialises (workflow-compute migrating its dashboard login codes is the most likely trigger). **Not built in this design.**

## Out of scope (deferred to Phase II or further)

- **Plugin changes.** No new step types, no proto changes, no module-config additions, no v0.3.0 tag of `workflow-plugin-auth`. The existing v0.2.4 surface is sufficient (passkey + magic-link + password steps all already present). Plugin extraction of the bootstrap-pipeline pattern is deferred until a second consumer needs it.
- **Cross-product SSO IDP surface** — `auth_jwt_issue` / `auth_jwt_verify` / `auth_jwks_serve` / refresh tokens. Separate Phase II design. workflow-compute feature-state.md §"Cross-product passwordless identity" tracks this as T411-T413.
- **`step.bmw.generate_token` retirement.** Cannot retire until Phase II SSO IDP ships an `auth_jwt_issue` step. Retained as-is. 9 existing call sites + 1 new (bootstrap-redeem) = 10 total.
- **`step.bmw.hash_password` retirement.** Cannot retire until Phase II plugin v0.2.5 ships configurable bcrypt cost. Retained as-is. Plugin's current `step.auth_password_hash` hardcodes `bcrypt.DefaultCost` (10); BMW bespoke uses 12. PR-3 swaps verify_password only.
- **SSH-key signature binding on bootstrap link.** User mentioned SSH-keys, but workflow-compute's actual pattern doesn't use them — codes are random tokens delivered out-of-band. Same pattern adopted. Future Phase II add if proof-of-possession proves valuable.
- **Replacing workflow-compute's existing dashboard login-codes flow.** Phase III follow-up; workflow-compute keeps bespoke path.

## Top doubts (resolved from cycle-1 + cycle-2 adversarial findings)

| Doubt (origin) | Resolution (rev 3) |
|---|---|
| BMW engine pin v0.20.1 vs plugin v0.2.4 pinning workflow v0.51.6 (cycle 2) | **PR-0 = BMW engine bump.** v0.20.1 predates strict-contracts force-cutover; plugin v0.2.4 gRPC handshake fails against this engine. Likely the real 500 source. Engine bump rebuilds BMW image, validates plugin handshake, runs golden-path smoke. Lands FIRST, before nil-deref hotfix. |
| Existing magic-link table name | `magic_link_tokens` (verified at app.yaml:7109/:7175/:7221). Bootstrap pipeline ALTERs to add `purpose TEXT DEFAULT 'login'` column; reuses existing table. |
| `step.bmw.generate_token` retirement story | Honest: bespoke step survives Phase 3, survives Phase II until SSO IDP lands. Phase 3 adds an 11th call site (bootstrap-redeem). No claim of "deferred retirement" — it's "retained as foundation". |
| Role gating for `/admin/enrol-passkey` | Gate to `role = 'super_admin'` strictly (not `IN ('admin','super_admin','moderator','support')`). Tenant-admin / moderator / support must not be conflated with platform super-admin. BMW RBAC schema verified (`migrations/20260308000001_add_rbac_permissions.up.sql:63`): roles are `'user', 'admin', 'super_admin', 'moderator', 'support'`. |
| Static bearer token for `/admin/bootstrap-link` | Explicitly **stopgap**. Listed as `BOOTSTRAP_OPERATOR_TOKEN` env var, NOT hardcoded; runbook says rotate per-deploy. Phase II followup: replace with mTLS or OS-process gate. |
| super_admins config source-of-truth | DB row, not config field. One-shot SQL seed in deploy runbook: `INSERT INTO users (email, role, ...) VALUES ('codingsloth@pm.me', 'super_admin', ...) ON CONFLICT (email) DO UPDATE SET role='super_admin' WHERE users.role NOT IN ('super_admin')`. Survives module-config rotation; no proto/plugin change needed. |
| Allowlist-miss response (timing oracle) | Bootstrap-link endpoint returns 200 with URL on allowlist-hit and 404 on miss (plan rev-10 — diverges from this row's earlier "constant 200" design; reconciled because the endpoint is operator-only behind a ≥32-char bearer token). **Known limitation:** the mint branch (HMAC + sha256 + DB INSERT) has wall-clock delta vs the no-mint branch — timing oracle in theory but accepted: only the operator can probe (bearer token), and the operator already knows the allowlist. If endpoint exposure widens, Phase II adds timing-equalisation (e.g., always-mint-then-conditionally-discard). |
| Concurrent-redeem race | Magic-link verify already uses `UPDATE … WHERE used_at IS NULL RETURNING id` (app.yaml:7221), single-row atomic claim. Bootstrap-redeem reuses this; first redeem wins, second redeem hits the post-UPDATE empty-RETURNING path → 401. |
| Plugin RPC pattern (cycle 1) | Dropped. BMW pipeline mints magic link inline via existing `step.auth_magic_link_generate`. No new gRPC service, no plugin CLI, no plugin binary CLI-vs-handshake dual-mode. |
| Map-round-trip on `CredentialModuleConfig` | Not relevant (no new proto fields). |
| `super_admins` allowlist as plugin step (rev 2) | Dropped. YAGNI — single consumer (BMW). Phase II will extract when second consumer arrives. |

## Phases & PR plan

### PR-0 — BMW workflow engine pin bump (probable real 500 source)

**Repo:** buymywishlist
**Depends on:** nothing.
**Risk class:** runtime — image rebuild, plugin handshake compatibility.

1. Bump `github.com/GoCodeAlone/workflow` in `buymywishlist/go.mod` from v0.20.1 to the version that matches `workflow-plugin-auth` v0.2.4's pin (currently v0.51.6).
2. `go mod tidy` + rebuild lockfile if any.
3. `wfctl validate app.yaml` against the new engine.
4. Local `docker compose up`; curl `/healthz`; curl all 6 auth routes (register, login, passkey×4) and capture HTTP status + body — establishes pre-Phase-1 baseline.
5. If engine-pin bump alone fixes the 500s (gRPC handshake unblocked), Phase 1 may have nothing to do or only minor nil-deref guards remain.
6. Build BMW container image; `docker run` smoke; `curl /healthz` returns 200.

**Rollback:** revert PR; BMW reverts to v0.20.1 + broken-500 baseline.

### PR-1 — BMW exhaustive nil-deref hotfix on auth pipelines

**Repo:** buymywishlist
**Depends on:** PR-0 merged (so we can see whether 500s persist after engine bump or were resolved by it).
**Risk class:** YAML template — no engine/migration/version-pin changes.

1. `grep -n "\.row\." app.yaml | grep -v "\.found"` — identify every unguarded `.row.` access.
2. Subset within auth pipelines (`auth-register`, `auth-login`, `passkey-*`): the investigator-confirmed 5 sites at `:1071, :1084, :1098, :6596, :6793` plus any others surfaced by exhaustive grep.
3. For each unguarded site, wrap dependent steps in `{{ if .steps.<name>.found }}…{{ else }}<typed JSON error>{{ end }}` blocks. Route not-found branches to structured-JSON 401/404 responses.
4. Reproduce all 8 scenarios locally (`docker compose up` + curl):
   - Signup with new email → 200.
   - Signup with existing email → 409.
   - Signup missing fields → 400.
   - Login with valid creds → 200 + JWT.
   - Login with unknown email → 401.
   - Login with inactive user → 403.
   - Passkey login with missing session → 401.
   - Passkey login with unknown credential → 401.
5. If signup additionally fails for non-nil-deref reasons (auth.credential module not loaded, password_enabled returning nil from `step.auth_methods_policy`, etc.) — root-cause inline.
6. Delegate Playwright run to an Agent (per workspace `feedback_delegate_validation_runs` memory).

**Rollback:** revert PR; YAML guards back to baseline.

### PR-2 — BMW admin bootstrap login flow

**Repo:** buymywishlist
**Depends on:** PR-1.
**Risk class:** migration + new HTTP routes + new YAML pipelines.

1. **Migration:** `ALTER TABLE magic_link_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'`. (Adds purpose discriminator on existing table.)
2. **Migration:** `INSERT INTO users (id, email, role, tenant_id, is_active, ...) VALUES (gen_random_uuid(), 'codingsloth@pm.me', 'super_admin', '<bmw_tenant_id>', true, ...) ON CONFLICT (email) DO UPDATE SET role='super_admin' WHERE users.role NOT IN ('super_admin');` — one-shot seed of platform super-admin.
2a. **Migration: patch existing magic-link pipeline writes** to set `purpose='login'` on INSERT (current INSERT at `app.yaml:7109` has no purpose value; default `'login'` covers it but explicit is safer). Patch existing SELECT at `app.yaml:7175` to add `AND purpose = 'login'` so admin-bootstrap tokens are not picked up by regular user login. Mirror for verify pipelines (e.g., `:7170`).
3. **Endpoint:** `POST /admin/bootstrap-link` — **publicly reachable** (http.server `:8080` all-interfaces + Tailscale `:443`); bearer token (≥32-char `BOOTSTRAP_OPERATOR_TOKEN` enforced inline) + DB-side single-active-token + 15-min TTL are the protections (see Assumption #2). Pipeline shape (per plan rev 11):
   - `step.request_parse` (parse_body:true, parse_headers:["X-Admin-Bootstrap-Token"]) → headers + body available downstream.
   - `step.set normalize_email` → `email: .body.email | lower | trimSpace` (BMW-wide convention).
   - `step.conditional check_token` → inline template combines `(ge (len (config "bootstrap_operator_token")) 32)` AND header == config; on mismatch → 401. Note: template `eq` is not constant-time; acceptable for operator-only endpoint, Phase II adds constant-time primitive.
   - `step.conditional check_email_allowed` → email matches `bootstrap_allowed_email` config (case-insensitive).
   - `step.db_query lookup_admin` → `WHERE lower(email) = $1 AND deleted_at IS NULL AND is_active = true LIMIT 1` (mode: single).
   - On allowlist + super_admin role match: `step.set set_generate_inputs`, `step.auth_magic_link_generate`, `step.db_query insert_token` (RETURNING id), `step.db_exec invalidate_prior` (excludes new row id).
   - Allowlist-hit: respond 200 with `{minted: true, magic_link_url, expires_at, message}`. Allowlist-miss: respond 404 `{error: not_eligible}`. (Timing-oracle accepted per Top Doubts row; operator-only audience.)
4. **Endpoint:** `GET /admin/bootstrap-redeem?email=…&token=…` — browser-clickable. The emailed URL at `app.yaml:7120` is a URL string in the email body, not an existing GET handler; this PR introduces the admin-side GET handler. Token in URL traded off for clickability; mitigated by single-use + 15-min TTL + operator-restricted scope. Pipeline:
   - `step.request_parse` (query_params: ["email", "token"]) → `.query.email` + `.query.token`.
   - `step.set normalize_email` → `email: .query.email | lower | trimSpace`.
   - `step.db_query find_bootstrap_token` → `WHERE lower(email) = $1 AND purpose = 'admin_bootstrap' AND used_at IS NULL AND expires_at > NOW()` (SQL-side TTL bypasses template→time.Parse round-trip).
   - `step.set set_verify_inputs` → token / stored_hash / expires_at.
   - `step.auth_magic_link_verify` → `.valid`.
   - `step.db_query mark_used` (mode: single, RETURNING id) — atomic single-use claim.
   - `step.db_query fetch_user` → `WHERE lower(email) = lower($1) AND is_active = true AND deleted_at IS NULL AND role = 'super_admin'` (defends against post-mint demotion / deactivation).
   - `step.set set_session_inputs` reads role from DB (not hardcoded).
   - `step.bmw.generate_token` (config: expiry: "24h") → JWT (call site #10).
   - Respond 200 `{session_token, redirect: "/api/v1/auth/admin/enrol-passkey/begin"}`. `redirect` is informational (no server-side 302); operator follows runbook.
5. **NEW admin pipelines:** `POST /api/v1/auth/admin/enrol-passkey/{begin,finish}` (additive; do NOT modify existing passkey-register routes which serve regular users). Same step graph as the existing passkey-register-* pipelines, with BMW role-gate pattern (auth_validate → fetch_role → flatten_role → check_super_admin) inserted BEFORE the existing `passkey_policy` step. Existing routes are preserved unchanged.
6. **Runbook (`docs/runbooks/admin-bootstrap.md` NEW):**
   - Deploy precondition: `[ ${#BOOTSTRAP_OPERATOR_TOKEN} -ge 32 ]` (runtime template enforces too).
   - Operator: `curl -X POST -H "Content-Type: application/json" -H "X-Admin-Bootstrap-Token: $BOOTSTRAP_OPERATOR_TOKEN" -d '{"email":"codingsloth@pm.me"}' https://buymywishlist.com/admin/bootstrap-link | jq .magic_link_url` → URL is in response body.
   - User opens URL (GET) → session granted → enrols passkey via `/api/v1/auth/admin/enrol-passkey/{begin,finish}` → bootstrap retired (passkey login replaces it).

**Rollback:** revert PR; bootstrap pipelines disabled; `magic_link_tokens.purpose` column harmless; seed row in `users` left in place (harmless; can be deleted manually).

### PR-3 — BMW verify_password migration to plugin (hash_password retained, see Phase II)

**Repo:** buymywishlist
**Depends on:** PR-2.
**Risk class:** YAML step-type rename (single call site).

1. **KEEP** `step.bmw.hash_password` (2 call sites: `app.yaml:881` register flow + `:11116` password reset flow). Plugin step uses `bcrypt.DefaultCost` (10); bespoke uses cost=12. Migration would silently downgrade newly-signed-up users' password security. Phase II opens plugin v0.2.5 with configurable cost; BMW migrates then.
2. Replace **2 call sites** `step.bmw.verify_password` → `step.auth_password_verify` (`app.yaml:1073` + `:9447`). Verify is cost-agnostic (reads cost from hash itself), so this swap is safe.
3. **KEEP** `step.bmw.generate_token` (10 call sites after PR-2). Retirement is Phase II SSO IDP scope.
4. End-to-end smoke: signup → login → password verify → bootstrap-redeem → passkey enrol → passkey login. All 6 scenarios still pass.
5. Bespoke `bmwplugin/step_auth.go` retains `hash_password` + `generate_token`; `verify_password` function can be deleted in a separate cleanup commit, or left in place (unused, harmless).

**Rollback:** revert PR; YAML reverts to bespoke step types; plugin step types stay registered (harmless).

### Phase II (deferred — interface sketches below acknowledge user's broader ask)

Phase II is the **reusable plugin extraction** the user asked for. Triggered when (a) PR-3 merges and BMW is stable, or (b) workflow-compute schedules migration of its dashboard login codes (T411-T413 in `workflow-compute/docs/feature-state.md`) — whichever comes first.

**Phase II contract sketch (1-page interface preview, not implementation):**

```text
# workflow-plugin-auth v0.2.5 — additive bcrypt cost configuration
step.auth_password_hash
  config:
    cost: int (default 10 = bcrypt.DefaultCost; range 4..31)

# workflow-plugin-auth v0.3.0 — admin bootstrap primitives
auth.bootstrap module type
  config:
    super_admins: [{email: string, default_role: string}]
    bootstrap_signing_secret: string  # HMAC for code generation
    code_ttl_seconds: int (default 600)

step.auth_super_admin_allowlist
  input: {email}
  config: super_admins list (read from auth.bootstrap module)
  output: {is_admin: bool, default_role: string}

step.auth_admin_bootstrap_code_generate  # alternative to magic-link reuse if plain-string-code UX is preferred
  input: {user_id, purpose}
  output: {code: string (one-shot), code_id: string}

step.auth_admin_bootstrap_code_verify
  input: {code}
  output: {user_id, granted_role, purpose}  OR  error {reason}

# workflow-plugin-auth v0.4.0 — Cross-product SSO IDP surface
auth.idp module type
  config:
    issuer: string
    audience: [string]
    signing_key_id: string  # key rotation hooks
    jwks_path: string (default /.well-known/jwks.json)

step.auth_jwt_issue
  input: {subject, claims}
  output: {token, expires_at, kid}

step.auth_jwt_verify
  input: {token}
  output: {subject, claims, expires_at}  OR  error

step.auth_jwks_serve  # HTTP module embedded in pipeline; serves /.well-known/jwks.json

step.auth_refresh_token_issue / step.auth_refresh_token_verify
```

**Phase II concrete follow-ups:**

- workflow-plugin-auth v0.2.5: add `cost` config to `step.auth_password_hash`. ~10 LOC + 1 proto field. Smallest possible PR.
- BMW migrates `step.bmw.hash_password` → `step.auth_password_hash` once v0.2.5 ships.
- workflow-plugin-auth v0.3.0: extract `auth.bootstrap` module + admin-bootstrap step types from BMW's PR-2 pipeline pattern.
- BMW migrates the inline `lookup_admin` + `step.auth_magic_link_generate` pattern to `step.auth_super_admin_allowlist` + `step.auth_admin_bootstrap_code_*`.
- workflow-plugin-auth v0.4.0: add `auth.idp` + JWT issue/verify steps.
- BMW retires `step.bmw.generate_token` (10 call sites) by swapping to `step.auth_jwt_issue`.
- workflow-compute migrates dashboard login codes onto `step.auth_admin_bootstrap_code_*`.
- Optional Phase II++: SSH-signature proof-of-possession on bootstrap-link redeem; mTLS / Unix-socket peer-cred replacement of `BOOTSTRAP_OPERATOR_TOKEN` bearer token; constant-time string comparison primitive in workflow engine.

## Assumptions (load-bearing)

1. **PR-0 verified before PR-1.** Engine bump from v0.20.1 to ≥v0.51.6 lands cleanly with no other code change required in BMW (no proto/struct-of-config breakage; existing pipelines using plugin steps remain semantically equivalent). *If false:* PR-0 grows to include any compatibility patches surfaced by `wfctl validate` + smoke; widens scope but doesn't change the plan.
2. **Bearer-token gate is the sole network protection.** http.server binds `:8080` all-interfaces (verified `app.yaml:248`); Tailscale exposes `:443`. ≥32-char `BOOTSTRAP_OPERATOR_TOKEN` (deploy precondition + runtime length-check) + per-deploy rotation + single-active-token DB invariant + 15-min TTL combine to make the endpoint operator-only in practice. Phase II hardening: mTLS / Unix-socket peer-cred replacement.
3. **`magic_link_tokens` table ALTER ADD COLUMN purpose is safe.** PostgreSQL is BMW's DB; ALTER ADD COLUMN with a DEFAULT is metadata-only (PG 11+, no full-table rewrite). Verified for the schema in current production.
4. **BMW deploy can run one-shot SQL seed** in a forward migration to insert the super-admin row. Existing migration runner (golang-migrate based, per the migrations/ directory pattern) supports this.
5. **`step.auth_password_verify` has input/output keys compatible with the bespoke `step.bmw.verify_password` call shape.** Verify is cost-agnostic (cost is embedded in bcrypt hash). Confirmed by reading `workflow-plugin-auth/internal/step_password.go:38-58`. (`step.auth_password_hash` is NOT swapped — see PR-3 step 1 — because `bcrypt.DefaultCost` mismatch silently downgrades new-user password security.)
6. **Operator delivers magic-link URL via secure channel** (1Password, Signal, direct console paste). Bootstrap pipeline not responsible for delivery.
7. **workflow-plugin-auth v0.2.4 stays as the BMW pin.** No plugin tag in this design. *If false:* unexpected scope creep; defer.

## Rollback (per change class)

| PR | Change class | Rollback |
|---|---|---|
| PR-0 | BMW workflow engine pin (v0.20.1 → v0.51.6+); rebuild image | Revert PR; BMW image rolls back to v0.20.1 + broken-500 baseline. Plugin handshake fails again but at least matches the prior state. |
| PR-1 | BMW YAML guard wrapping (no engine/migration changes) | Revert PR; nil-deref vulnerability returns. |
| PR-2 | BMW migration (ALTER + seed) + new admin pipelines + 1 new HTTP endpoint pair | Revert PR; admin endpoints disabled; ALTER COLUMN left (harmless); seed row left (harmless; manual delete if desired). |
| PR-3 | BMW YAML step-type rename for 2 call sites | Revert PR; bespoke steps return; plugin steps stay registered (harmless). |

## Verification gates

- **PR-0:** `docker compose up` boots BMW with new engine pin; `/healthz` 200; PR description quotes pre-bump vs post-bump HTTP-status table for all 6 auth routes. **Success gate is conceptually merged with PR-1:** PR-0 alone may leave 500s if root cause is nil-deref not handshake; PR-1 must close the loop. The combined gate is: after PR-0 + PR-1 merged, all 8 scenarios in §PR-1 step 4 return their **expected** status code + body shape (not just `!= 500`).
- **PR-1:** All 8 manual curl scenarios in §PR-1 step 4 pass; `wfctl validate app.yaml` green; Playwright smoke green (delegated to Agent).
- **PR-2:** Migration applies cleanly forward + reverse; bootstrap endpoint mints URL; redeem creates valid JWT session; concurrent-redeem race serialised correctly; allowlist-miss returns timing-safe 200; `/admin/enrol-passkey` rejects non-super_admin sessions.
- **PR-3:** All 6 auth scenarios pass with plugin-backed password steps; bootstrap-redeem still mints JWT (call site #11 of `step.bmw.generate_token` works); no other regression.

## File touch surface (approximate)

| Repo | Files touched | Approx LOC |
|---|---|---|
| buymywishlist | go.mod (PR-0); app.yaml (PR-1 ~30 lines; PR-2 ~150 lines bootstrap pipelines; PR-3 ~6 lines step rename); migrations/NNNN_alter_magic_link_tokens_purpose.up.sql + .down.sql (NEW, ~6 LOC); migrations/NNNN_seed_super_admin.up.sql + .down.sql (NEW, ~10 LOC); docs/runbooks/admin-bootstrap.md (NEW) | ~200 |
| workflow-plugin-auth | none | 0 |

## Sequencing & PR plan summary

| PR | Repo | Scope | Depends on |
|---|---|---|---|
| PR-0 | buymywishlist | Engine pin bump | (none) |
| PR-1 | buymywishlist | Nil-deref hotfix | PR-0 |
| PR-2 | buymywishlist | Admin bootstrap pipelines + migration | PR-1 |
| PR-3 | buymywishlist | Password step migration to plugin | PR-2 |

Sequential. PR-0 is the riskiest (engine pin straddles strict-contracts cutover) and possibly the most impactful (fixes the 500s if they're handshake-level). PRs 1-3 are additive YAML/migration work each rollback-clean.

## References

- workflow-compute dashboard login codes: `workflow-compute/internal/server/auth.go:1413` (defaultTokenGenerator), `:1055` (createDashboardLoginCode), `:1131` (createDashboardSession), CLI `cmd/compute/main.go:369` (login-codes create).
- workflow-compute feature gap: `workflow-compute/docs/feature-state.md:82` (Cross-product passwordless identity, T411-T413).
- BMW current auth: `buymywishlist/app.yaml:784` (register), `:999` (login), `:6485..:6720` (passkey routes).
- BMW magic-link existing pipeline: `app.yaml:7103..:7221` (already uses `step.auth_magic_link_*` against `magic_link_tokens` table).
- BMW nil-deref sample sites (audit must scan exhaustively): `:1071, :1084, :1098, :6596, :6793`.
- BMW `step.bmw.generate_token` call sites (9 verified via `grep -c`, retained — Phase II retires): `:668, :1103, :6848, :7023, :7241, :7571, :7625, :7887, :10940` + 1 new in bootstrap-redeem (= 10 total).
- BMW RBAC schema: `migrations/20260308000001_add_rbac_permissions.up.sql:63` (CHECK constraint: `role IN ('user', 'admin', 'super_admin', 'moderator', 'support')`).
- BMW engine pin: `buymywishlist/go.mod:7` = `github.com/GoCodeAlone/workflow v0.20.1` (predates strict-contracts cutover).
- workflow-plugin-auth current: v0.2.4, pins `workflow v0.51.6`, strict-proto contracts (`internal/plugin.go:265-300`).
- workflow-plugin-auth password steps: `internal/step_password.go:23` (hash uses `bcrypt.DefaultCost` = 10; BMW bespoke uses cost 12 — hash NOT swapped in PR-3, see Phase II); `internal/step_password.go:38-58` (verify is cost-agnostic — swapped in PR-3).
- workflow-plugin-auth magic-link API: `internal/step_magic_link.go:23-99` (stateless: caller stores token_hash).
