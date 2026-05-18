# Admin Bootstrap + Passkey Upgrade — Design (2026-05-17, rev 3)

> **Revision history:** rev 1 → rev 2 → rev 3 (this doc) following two adversarial-design-review FAIL cycles. Key change in rev 3: dropped all plugin work (no new step types, no proto changes, no v0.3.0 tag). All work is BMW-side. Plugin "reusable extraction" deferred to Phase II when a second consumer materialises (YAGNI). Critical findings from cycle 2 resolved: (a) promoted BMW engine pin bump from v0.20.1 to a first-class PR-0 (likely proximate cause of current 500s — gRPC strict-contract handshake fails against old engine), (b) reuse existing `magic_link_tokens` table (not invent `auth_magic_links`), (c) acknowledged bespoke `step.bmw.generate_token` survives this design.

## Goal

1. Restore BuyMyWishlist (BMW) **signup AND login** (both currently HTTP 500). Root cause is suspected to be plugin-engine handshake failure (BMW pins workflow v0.20.1; existing in-use auth-plugin pipelines target v0.51.6-era strict-proto contracts), with template nil-derefs as secondary fragility surface. Both addressed.
2. Stand up an **admin bootstrap login flow** for BMW operator (`codingsloth@pm.me`): operator triggers magic-link mint via a localhost-bound BMW endpoint → URL → user redeems → JWT session → enrols passkey via existing passkey routes → subsequent logins use passkey; bootstrap is break-glass only.
3. Migrate BMW's two trivial password steps onto plugin equivalents (`step.bmw.hash_password` → `step.auth_password_hash`, `step.bmw.verify_password` → `step.auth_password_verify`). Bespoke `step.bmw.generate_token` retained (10 existing + 1 new call site in bootstrap-redeem = 11 total; no plugin replacement exists today).
4. Document a forward path for cross-product SSO (issuer, JWKS endpoint, refresh tokens, JWT issue/verify) and plugin extraction of the bootstrap pattern as **Phase II**, triggered when a second consumer materialises (workflow-compute migrating its dashboard login codes is the most likely trigger). **Not built in this design.**

## Out of scope (deferred to Phase II or further)

- **Plugin changes.** No new step types, no proto changes, no module-config additions, no v0.3.0 tag of `workflow-plugin-auth`. The existing v0.2.4 surface is sufficient (passkey + magic-link + password steps all already present). Plugin extraction of the bootstrap-pipeline pattern is deferred until a second consumer needs it.
- **Cross-product SSO IDP surface** — `auth_jwt_issue` / `auth_jwt_verify` / `auth_jwks_serve` / refresh tokens. Separate Phase II design. workflow-compute feature-state.md §"Cross-product passwordless identity" tracks this as T411-T413.
- **`step.bmw.generate_token` retirement.** Cannot retire until Phase II SSO IDP ships an `auth_jwt_issue` step. Retained as-is. 10 existing call sites + 1 new (bootstrap-redeem) = 11 total.
- **SSH-key signature binding on bootstrap link.** User mentioned SSH-keys, but workflow-compute's actual pattern doesn't use them — codes are random tokens delivered out-of-band. Same pattern adopted. Future Phase II add if proof-of-possession proves valuable.
- **Replacing workflow-compute's existing dashboard login-codes flow.** Phase III follow-up; workflow-compute keeps bespoke path.

## Top doubts (resolved from cycle-1 + cycle-2 adversarial findings)

| Doubt (origin) | Resolution (rev 3) |
|---|---|
| BMW engine pin v0.20.1 vs plugin v0.2.4 pinning workflow v0.51.6 (cycle 2) | **PR-0 = BMW engine bump.** v0.20.1 predates strict-contracts force-cutover; plugin v0.2.4 gRPC handshake fails against this engine. Likely the real 500 source. Engine bump rebuilds BMW image, validates plugin handshake, runs golden-path smoke. Lands FIRST, before nil-deref hotfix. |
| Existing magic-link table name | `magic_link_tokens` (verified at app.yaml:7109/:7175/:7221). Bootstrap pipeline ALTERs to add `purpose TEXT DEFAULT 'login'` column; reuses existing table. |
| `step.bmw.generate_token` retirement story | Honest: bespoke step survives Phase 3, survives Phase II until SSO IDP lands. Phase 3 adds an 11th call site (bootstrap-redeem). No claim of "deferred retirement" — it's "retained as foundation". |
| Role gating for `/admin/enrol-passkey` | Gate to `role = 'super_admin'` strictly (not `IN ('admin','super_admin')`). Tenant-admin must not be conflated with platform super-admin. BMW RBAC schema verified (`migrations/20260308000001_add_rbac_permissions.up.sql`): roles are `super_admin / admin / operator / viewer`. |
| Static bearer token for `/admin/bootstrap-link` | Explicitly **stopgap**. Listed as `BOOTSTRAP_OPERATOR_TOKEN` env var, NOT hardcoded; runbook says rotate per-deploy. Phase II followup: replace with mTLS or OS-process gate. |
| super_admins config source-of-truth | DB row, not config field. One-shot SQL seed in deploy runbook: `INSERT INTO users (email, role, ...) VALUES ('codingsloth@pm.me', 'super_admin', ...) ON CONFLICT (email) DO UPDATE SET role='super_admin' WHERE users.role NOT IN ('super_admin')`. Survives module-config rotation; no proto/plugin change needed. |
| Allowlist-miss response (timing oracle) | Bootstrap-link endpoint always returns the same 200 response (`{"sent": true, "message": "If your email is allowlisted, a link has been delivered"}`) regardless of allowlist match. Internal branching on `users.role='super_admin'` controls the actual magic-link mint. |
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
3. **Endpoint:** `POST /admin/bootstrap-link` (configured to bind localhost-only via existing BMW ingress / listener config). Header `X-Admin-Bootstrap-Token: $BOOTSTRAP_OPERATOR_TOKEN` (env-var-sourced; runbook documents rotation per deploy). Pipeline:
   - Parse body `{email}`.
   - `step.set check_token` validates `X-Admin-Bootstrap-Token` header equals config `bootstrap_operator_token`.
   - `step.db_query lookup_admin`: `SELECT id, role FROM users WHERE email = $1 AND role = 'super_admin'`.
   - `step.conditional` on `lookup_admin.found`:
     - both branches return the SAME `{sent: true, message: "If your email is allowlisted, a link has been delivered"}` response (timing-safe).
     - branch on `true`: call `step.auth_magic_link_generate` with email + signing_secret={{ config "jwt_secret" }} + expiry_minutes=10 → store `(token_hash, email, expires_at, purpose='admin_bootstrap')` in `magic_link_tokens` → write URL to response payload.
4. **Endpoint:** `GET /admin/bootstrap-redeem?token=<token>`. Pipeline:
   - `step.db_query find_bootstrap_token`: `SELECT id, token_hash, expires_at, email FROM magic_link_tokens WHERE purpose='admin_bootstrap' AND used_at IS NULL ORDER BY created_at DESC LIMIT 1` (filtered by email if present in query string, else by token-hash if BMW prefers stateless).
   - `step.auth_magic_link_verify` against `find_bootstrap_token.row`.
   - `step.db_exec mark_used`: `UPDATE magic_link_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL RETURNING id`. If no row returned (concurrent redeem), respond 401.
   - `step.bmw.generate_token` to mint JWT session with `role=super_admin` (call site #11 — bespoke step retained).
   - Redirect to `/admin/enrol-passkey`.
5. **UI surface:** `/admin/enrol-passkey` — existing passkey-register-begin / passkey-register-finish routes ALREADY exist (app.yaml:6485/6549). Gate access at the route level to `role='super_admin'` (strictly; not `IN ('admin','super_admin')`).
6. **Runbook (`docs/runbooks/admin-bootstrap.md` NEW):**
   - Set `BOOTSTRAP_OPERATOR_TOKEN` env var on BMW deploy (rotate per deploy).
   - Operator: `curl --unix-socket /var/run/bmw.sock -H "X-Admin-Bootstrap-Token: $BOOTSTRAP_OPERATOR_TOKEN" -d '{"email":"codingsloth@pm.me"}' http://localhost/admin/bootstrap-link` → returns magic URL in response body.
   - User opens URL in browser → session granted → enrols passkey → bootstrap retired (passkey login replaces it).

**Rollback:** revert PR; bootstrap pipelines disabled; `magic_link_tokens.purpose` column harmless; seed row in `users` left in place (harmless; can be deleted manually).

### PR-3 — BMW password step migration to plugin

**Repo:** buymywishlist
**Depends on:** PR-2.
**Risk class:** YAML step-type rename.

1. Replace 1 call site `step.bmw.hash_password` → `step.auth_password_hash` (app.yaml:881).
2. Replace 1 call site `step.bmw.verify_password` → `step.auth_password_verify` (app.yaml:1073).
3. **KEEP** `step.bmw.generate_token` (11 call sites). Retirement is Phase II SSO IDP scope.
4. Verify input/output keys match between bespoke and plugin equivalents (likely identical; both wrap bcrypt at cost=12).
5. End-to-end smoke: signup → login → password verify → bootstrap-redeem → passkey enrol → passkey login. All 6 scenarios still pass.
6. Bespoke `bmwplugin/step_auth.go` retains `generate_token` only; `hash_password` + `verify_password` functions can be left in place (unused) or deleted in a separate cleanup commit.

**Rollback:** revert PR; YAML reverts to bespoke step types; plugin step types stay registered (harmless).

### Phase II (deferred)

- workflow-plugin-auth: extract `auth_jwt_issue` / `auth_jwt_verify` / hosted-JWKS / refresh-token steps. Separate design doc.
- workflow-plugin-auth: extract `auth_super_admin_allowlist` step + bootstrap-link pipeline pattern when a 2nd consumer needs it.
- BMW: retire `step.bmw.generate_token` (11 call sites) by swapping to `step.auth_jwt_issue`.
- workflow-compute: migrate dashboard login codes onto extracted bootstrap pattern.
- Optional SSH-signature proof-of-possession on bootstrap-link redeem.
- Replace stopgap `BOOTSTRAP_OPERATOR_TOKEN` with mTLS / OS-process gate.

## Assumptions (load-bearing)

1. **PR-0 verified before PR-1.** Engine bump from v0.20.1 to ≥v0.51.6 lands cleanly with no other code change required in BMW (no proto/struct-of-config breakage; existing pipelines using plugin steps remain semantically equivalent). *If false:* PR-0 grows to include any compatibility patches surfaced by `wfctl validate` + smoke; widens scope but doesn't change the plan.
2. **BMW ingress can localhost-bind `/admin/bootstrap-link`** or, failing that, the env-var-sourced bearer token + per-deploy rotation is acceptable as a stopgap. *If false:* operator must rotate token via Phase II proper hardening.
3. **`magic_link_tokens` table ALTER ADD COLUMN purpose is safe.** PostgreSQL is BMW's DB; ALTER ADD COLUMN with a DEFAULT is metadata-only (PG 11+, no full-table rewrite). Verified for the schema in current production.
4. **BMW deploy can run one-shot SQL seed** in a forward migration to insert the super-admin row. Existing migration runner (golang-migrate based, per the migrations/ directory pattern) supports this.
5. **`step.auth_password_hash` and `step.auth_password_verify` have input/output keys compatible with the bespoke `step.bmw.hash_password` / `step.bmw.verify_password` call shape.** Both wrap bcrypt; the plugin step is the canonical version. Confirmed by reading `workflow-plugin-auth/internal/step_password.go`. *If false:* PR-3 expands to YAML adapter glue.
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

- **PR-0:** `docker compose up` boots BMW with new engine pin; `/healthz` 200; all 6 auth routes return non-500 status codes (which may or may not be successful auth, but no engine-side panic). PR description quotes pre-bump vs post-bump status codes side-by-side.
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
- BMW `step.bmw.generate_token` call sites (retained — Phase II retires): `:668, :1103, :6848, :7023, :7240, :7241, :7571, :7625, :7887, :10940` + 1 new in bootstrap-redeem (= 11 total).
- BMW RBAC schema: `migrations/20260308000001_add_rbac_permissions.up.sql` (roles: `super_admin / admin / operator / viewer`).
- BMW engine pin: `buymywishlist/go.mod:7` = `github.com/GoCodeAlone/workflow v0.20.1` (predates strict-contracts cutover).
- workflow-plugin-auth current: v0.2.4, pins `workflow v0.51.6`, strict-proto contracts (`internal/plugin.go:265-300`).
- workflow-plugin-auth password steps: `internal/step_password.go` (bcrypt cost=12, identical to bespoke `step.bmw.hash_password` / `verify_password`).
- workflow-plugin-auth magic-link API: `internal/step_magic_link.go:23-99` (stateless: caller stores token_hash).
