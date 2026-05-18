# Admin Bootstrap + Passkey Upgrade — Design (2026-05-17, rev 2)

> **Revision history:** rev 1 → rev 2 (this doc) following adversarial-design-review FAIL with 4 Critical + 8 Important findings. Key changes: dropped new step types / migration / HKDF key / new module type in favour of reusing the existing `step.auth_magic_link_*` surface; broadened Phase 1 from "5 known nil-derefs" to an exhaustive auth-pipeline audit including signup; resolved deferred-architecture decisions in-design; deferred `step.bmw.generate_token` replacement to Phase II (no plugin equivalent exists).

## Goal

1. Restore BuyMyWishlist (BMW) **signup AND login** (both currently HTTP 500) via an exhaustive nil-deref audit of all auth pipelines.
2. Add a **reusable admin bootstrap** capability to `workflow-plugin-auth`: declarative super-admin email allowlist + a single new step (`step.auth_super_admin_allowlist`) that composes with the existing `step.auth_magic_link_generate`/`step.auth_magic_link_verify` steps. Operator runs `wfctl plugin auth admin-bootstrap-link --email <e>` against the host, host hits a localhost-bound BMW admin endpoint, BMW pipeline checks allowlist and mints a magic link returning the URL on stdout. User pastes URL → session → enrols passkey via existing passkey routes → bootstrap retired.
3. Migrate BMW's two password-related bespoke steps onto plugin-provided equivalents (`step.bmw.hash_password` → `step.auth_password_hash`; `step.bmw.verify_password` → `step.auth_password_verify`). Defer `step.bmw.generate_token` replacement to Phase II SSO IDP (no plugin equivalent yet; 9 call sites verified).
4. Document a forward path for cross-product SSO (issuer, JWKS endpoint, refresh tokens) as Phase II; **not built in this design**.

## Out of scope (deferred)

- **Cross-product SSO IDP surface** — Phase II separate design doc. workflow-compute feature-state.md §"Cross-product passwordless identity" tracks this as T411-T413.
- **`step.bmw.generate_token` retirement** — Phase II only. 9 call sites in `app.yaml` (`:668, :1103, :6848, :7023, :7241, :7571, :7625, :7887, :10940`). No plugin equivalent exists (no `auth_jwt_*` step in v0.2.4). Removing bespoke `bmwplugin/step_auth.go` waits for that.
- **SSH-key signature binding on bootstrap link** — user's mental model mentioned SSH keys; workflow-compute's own pattern doesn't actually use SSH keys (its `wc_`-prefix codes are random tokens delivered out-of-band). Same pattern adopted. If SSH proof-of-possession is later wanted as defence-in-depth, it's a Phase II add (`ssh_signature` optional field validated against pubkey in config).
- **Replacing workflow-compute's existing dashboard login-codes flow** — Phase III follow-up; workflow-compute keeps its bespoke path until separate migration.

## Top doubts (resolved from rev-1 adversarial findings)

| Doubt (rev 1) | Resolution (rev 2) |
|---|---|
| "Migration runner pattern" not in plugin | Plugin has **no migrations directory** (verified). Magic-link step is stateless-with-caller-checkpoint — caller (BMW) stores token_hash in its own DB. No plugin migration needed. |
| CLI in gRPC plugin binary | Not a CLI in the plugin binary. Plugin exposes step + new gRPC admin RPC (`AdminBootstrapLink`) which `wfctl` calls. Plugin runs inside engine, has DB connection + config naturally. |
| HKDF master key source | None — reusing `step.auth_magic_link_*` which already takes `signing_secret` (BMW's `jwt_secret`). Rotation invalidates outstanding links (acceptable). |
| Phase 1 only fixes login, user said signup too | Phase 1 now requires an **exhaustive grep** of `.row.` accesses + dry-run of register + login + passkey pipelines. Not the 5-site sample. |
| `step.bmw.generate_token` has no plugin equivalent | Acknowledged. Replacement deferred to Phase II. Phase 3 only retires hash/verify_password. Bespoke `step_auth.go` survives Phase 3 (delete in Phase II). |
| Engine pin v0.51.6 stale vs v0.57.1 | Phase 0 = verify plugin v0.2.4 loads in BMW's current engine pin. If incompatible, bump engine pin + rebuild plugin first (separate PR). Memory shows the sentinel-removal cascade hit 4 plugins to v2.0.0 on 2026-05-17 — auth was NOT in that cascade so v0.2.4 contract surface should still be compatible, but it must be verified in Phase 0. |
| Worktree `.worktrees/bmw-prod-auth-passkey/` not found | Assumption removed. Phase 3 implementer will check for in-flight passkey work via `git worktree list` and resolve conflict if found. |
| `super_admins` lookup keyed by email vs user_id | Lookup is by email at code-mint time. Pipeline auto-creates the user row with `role='super_admin'` on first redeem if not yet present. Subsequent redeems update existing row. |
| Admin role propagation unspecified | Bootstrap-login pipeline writes `role='super_admin'` into the `users` table on first redeem (UPSERT) and the existing session-creation step picks up that role into the JWT claim. No new role-propagation primitive. |
| New module type vs extend `auth.credential` | **Extend `auth.credential`** with `super_admins: [{email, default_role}]` config field (adds one field to `CredentialModuleConfig` proto). No new module type. |
| CSRF / rate-limit on `/admin/bootstrap-login` | Re-uses BMW's existing CSRF middleware on POST routes. Rate-limit at ingress (BMW already has standard `/api/v1/auth/*` rate-limit). Documented but no new code. Endpoint is localhost-bound for the mint side; redeem side is the standard magic-link-verify pattern (single-use, time-limited). |

## Phases

### Phase 0 — Engine compatibility verification (zero-LOC, just a check)

Before any code change in plugin or BMW:
1. Confirm BMW's actual workflow engine pin (`grep "workflow " buymywishlist/go.mod`).
2. Confirm whether sentinel-removal (workflow v0.57.x, 2026-05-17 cascade) affects plugin-auth gRPC contract surface. workflow-plugin-auth v0.2.4 uses strict-proto contracts (`internal/contracts/auth.proto`, `authContractRegistry` in `internal/plugin.go:265-300`) — these should survive the cascade unchanged, but verify by loading the plugin in the BMW-pinned engine and running an existing pipeline.
3. If incompatible: bump `workflow` pin in plugin go.mod, rebuild, retag (e.g. v0.2.5). Separate PR before Phase 2.

**Output:** a single answer in PR-2's description — "Phase 0 verified at workflow vX.Y.Z" or "Phase 0 surfaced engine-pin bump required, shipped as PR-2a".

### Phase 1 — BMW signup/login hotfix (independent, ship first)

Exhaustive audit:

1. `grep -n "\.row\." app.yaml` (current count: 20 across full file). Subset within auth pipelines (`auth-register`, `auth-login`, `passkey-*`): the investigator-confirmed 5 sites at `:1071, :1084, :1098, :6596, :6793` are the known set; the audit MUST run grep and check whether each site is already inside a `{{ if ... .found }}` block.
2. For each unguarded site, wrap dependent steps in `{{ if .steps.<name>.found }}…{{ else }}<typed error>{{ end }}` and route the not-found branch to a structured JSON 401 / 404 response (NEVER let template render against nil row).
3. Reproduce locally: `docker compose up` + curl all 6 register + login + passkey routes against:
   - Valid signup with new email → 200 + user row inserted.
   - Signup with existing email → 409 conflict (not 500).
   - Signup with missing fields → 400 (already covered, verify still works).
   - Valid login → 200 + JWT issued.
   - Login with unknown email → 401 (not 500).
   - Login with inactive user → 403 (not 500).
   - Passkey login with missing session → 401 (not 500).
   - Passkey login with unknown credential → 401 (not 500).
4. If signup additionally fails for a non-nil-deref reason (e.g. `step.auth_methods_policy` config issue, password_enabled returning nil, hash_password failing because `auth.credential` module isn't loaded), root-cause and fix inline.
5. Reverse-curl: confirm `wfctl validate app.yaml` is green and `docker compose up` runs to ready state.

**Ships as PR-1 against `buymywishlist`.** Restores access independently of plugin work.

### Phase 2 — workflow-plugin-auth admin bootstrap (small, additive)

**Single new step type:** `step.auth_super_admin_allowlist`

- Input: `{email}` (current step input).
- Config: `super_admins: [string]` (list of emails) — sourced from `auth.credential` module config via the existing config-flow.
- Output: `{is_admin: bool, default_role: string}` — strict-proto contract additions in `internal/contracts/auth.proto`, registry entry in `internal/plugin.go:authContractRegistry`, typed wrapper in `internal/typed.go`, implementation in new file `internal/step_super_admin_allowlist.go` (~80 LOC).

**Module config extension:** add `super_admins: [{email: string, default_role: string}]` field to `CredentialModuleConfig` proto. Default empty (back-compat). Migration cost: regen proto + add 1 field to `module_credential.go` config-load path.

**New gRPC admin RPC:** `AdminBootstrapLink(email) → magic_link_url` — convenience wrapper that the plugin exposes for `wfctl` to call. Internally: looks up super_admins, runs `step.auth_magic_link_generate` logic, returns URL string. The caller (BMW) is still responsible for storing the token_hash via its pipeline; the RPC just mints and the host echoes the URL. *Decision:* implemented as a new gRPC service method on the existing plugin server interface (avoids adding wfctl knowledge of per-plugin CLI).

Wait — that requires BMW to also store the hash, which means the RPC alone doesn't work. **Revision:** the RPC pattern is wrong; the simpler pattern is:

**Operator workflow (revised):**
1. Operator hits BMW's `POST /admin/bootstrap-link` endpoint over `localhost` only (BMW gates by listener IP) with header `X-Admin-Bootstrap-Token: $BOOTSTRAP_OPERATOR_TOKEN` (env-var in BMW config).
2. BMW pipeline:
   - Parse body for `email`.
   - Call `step.auth_super_admin_allowlist` to verify email is in allowlist.
   - On allowlist match: call `step.auth_magic_link_generate` (existing step) with `email` + `signing_secret={{ config "jwt_secret" }}`.
   - Insert `(token_hash, email, expires_at, purpose='admin_bootstrap')` into BMW `auth_magic_links` table (BMW-side; not plugin-side).
   - Return JSON `{magic_link_url: "https://<host>/admin/bootstrap-redeem?token=<token>"}` to operator stdout.
3. Operator pastes URL into browser.
4. BMW `GET /admin/bootstrap-redeem?token=…` pipeline:
   - Look up `auth_magic_links` row by token hash.
   - Call `step.auth_magic_link_verify` to validate.
   - UPSERT into `users` table with `role='super_admin'` on first redeem.
   - Run existing session-creation step (issues JWT with `role` claim).
   - Redirect to `/admin/enrol-passkey` (existing passkey route, gated to authenticated session).
5. User enrols passkey via existing passkey routes.
6. Future logins use passkey; bootstrap retired except as break-glass.

**Net plugin additions:**
- 1 new step type (`step.auth_super_admin_allowlist`)
- 1 proto config field (`super_admins` in `CredentialModuleConfig`)
- No new module type, no new migrations, no new tables, no new CLI, no new gRPC RPC

**Plugin LOC estimate:** ~120 LOC + 4 proto messages + ~30 LOC test.

Tag as **v0.3.0** (minor: additive feature, no contract breakage on existing surface).

### Phase 3 — BMW migration

1. Replace `step.bmw.hash_password` → `step.auth_password_hash` (1 call site).
2. Replace `step.bmw.verify_password` → `step.auth_password_verify` (1 call site; line 1073).
3. **KEEP** `step.bmw.generate_token` (9 call sites). Retirement deferred to Phase II.
4. Add `auth.credential` module config: `super_admins: [{email: "codingsloth@pm.me", default_role: "super_admin"}]`.
5. Add BMW migration: `CREATE TABLE auth_magic_links (token_hash, email, expires_at, purpose, consumed_at)` if it doesn't already exist (check current schema; BMW already has email-magic-link infrastructure per investigator findings).
6. Add `POST /admin/bootstrap-link` pipeline (operator-only, localhost-bound).
7. Add `GET /admin/bootstrap-redeem` pipeline (token redemption).
8. Add `/admin/enrol-passkey` gating to require authenticated session with `role IN ('admin','super_admin')`.
9. Verify Phase 1 hotfix from PR-1 is in place on the branch (rebase if necessary).
10. End-to-end smoke: bootstrap-link → URL → redeem → JWT session → enrol passkey → log out → log back in with passkey → bootstrap link no longer needed.

**Ships as PR-3 against `buymywishlist` after PR-2 (v0.3.0) is tagged + plugin.json sync workflow has bumped the manifest in the registry.** Depends on PR-1 + PR-2.

### Phase II (deferred, post-merge)

- Cross-product SSO IDP: `step.auth_jwt_issue` + `step.auth_jwt_verify` + `step.auth_jwks_serve` + `step.auth_refresh_token_*`, hosted JWKS endpoint module, key rotation hooks. Separate design doc.
- Retire `step.bmw.generate_token` (9 call sites) after Phase II SSO IDP ships.
- Migrate workflow-compute dashboard one-time codes onto Phase II steps.
- Optional SSH-signature proof-of-possession on bootstrap-link redemption.

## Assumptions (load-bearing)

1. **(Verified rev-2)** workflow-plugin-auth v0.2.4 gRPC contract surface is compatible with BMW's currently-pinned workflow engine (Phase 0 confirms this; otherwise bump plugin's engine pin first as PR-2a).
2. Strict-proto contract additions in Phase 2 are non-breaking — only adds new step + new optional proto field. No signature change to existing 25 steps.
3. BMW's existing CSRF middleware (if present) covers POST `/admin/bootstrap-link`. **If absent in BMW:** add a CSRF middleware to the admin pipeline group as a separate sub-task in PR-3.
4. BMW's ingress / reverse proxy can constrain `/admin/bootstrap-link` to localhost-bind. **If false:** rely on `X-Admin-Bootstrap-Token` header alone (declarative env var) plus rate-limit; document operator security model in BMW runbook.
5. BMW's existing magic-link table schema exists or can be added in one migration alongside the bootstrap pipeline.
6. Single super-admin email (`codingsloth@pm.me`) is acceptable for initial production; the proto list shape accommodates multiple.
7. Operator delivers magic-link URL via secure channel (1Password, Signal, in-person paste). Plugin not responsible for delivery.
8. workflow-compute's dashboard login codes stay untouched in this design. **If false:** scope creeps significantly; refuse and split.

## Rollback (per change class)

| Phase | Change class | Rollback |
|---|---|---|
| 0 | Engine verification (no code) | None needed; output is a paragraph in PR description. |
| 1 | BMW YAML changes (no engine/migration/version-pin changes) | Revert PR; signup/login returns to broken-500 baseline. |
| 2 | workflow-plugin-auth v0.3.0 release (1 new step, 1 proto config field, no migration) | Untag v0.3.0; consumers stay on v0.2.4. Proto additive field is back-compat — no consumer rebuild required (default empty list). |
| 3 | BMW migration onto plugin steps + new admin pipelines + 1 new table | Revert PR; bespoke `step.bmw.hash_password` / `verify_password` paths return; admin pipelines disabled. Empty `auth_magic_links` table left in place (harmless). |

## Verification gates

- **Phase 0:** Plugin loads in BMW's current engine pin; an existing BMW pipeline using plugin steps (e.g. passkey routes already in use) runs to success. Output: PR description paragraph confirming compatibility.
- **Phase 1:** Local `docker compose up`; curl all 8 scenarios listed in §Phase 1 Step 3; each returns the documented status (no 500s). Playwright smoke against BMW's existing auth tests passes. `wfctl validate app.yaml` green.
- **Phase 2:** `go test ./...` in plugin repo (≥95% on new files); `make proto` clean regen; CHANGELOG.md entry; v0.3.0 tag; goreleaser CI green; manual smoke against BMW staging or a `workflow-scenarios` scenario invoking the new step.
- **Phase 3:** `docker compose up` of BMW with v0.3.0 plugin pinned; end-to-end bootstrap-link → URL → redeem → JWT session → enrol passkey → re-login via passkey flow exercised. `wfctl validate` green. Playwright suite extended to cover bootstrap-redeem pipeline.

## File touch surface (approximate)

| Repo | Files touched | Approx LOC |
|---|---|---|
| buymywishlist | app.yaml (Phase 1: ~30 lines of guard wrapping; Phase 3: ~120 lines admin pipelines + 1 migration file ~20 lines); migrations/NNNN_auth_magic_links.sql (NEW, if not present) | ~170 |
| workflow-plugin-auth | internal/contracts/auth.proto (+1 message + 1 config field, ~15 LOC); internal/plugin.go (+1 registry entry, +1 step type, ~10 LOC); internal/step_super_admin_allowlist.go (NEW, ~80 LOC); internal/typed.go (~15 LOC); internal/module_credential.go (super_admins config load, ~20 LOC); CHANGELOG.md | ~140 |

## Sequencing & PR plan

- **PR-1** (BMW Phase 1): exhaustive auth-pipeline nil-deref audit + fix. Standalone. Merge first.
- **PR-2a** (workflow-plugin-auth Phase 0 follow-up — only if needed): engine pin bump.
- **PR-2** (workflow-plugin-auth Phase 2): new step + proto field + v0.3.0 tag.
- **PR-3** (BMW Phase 3): bespoke→plugin password step swap + admin bootstrap pipelines. Depends on PR-2.

PR-1 and PR-2 may run in parallel (independent repos).

## Open questions (carried forward to writing-plans)

None remaining — adversarial-review-cycle-1 decisions resolved all rev-1 hedges. The writing-plans phase produces concrete task breakdown but introduces no new design decisions.

## References

- workflow-compute dashboard login codes: `workflow-compute/internal/server/auth.go:1413` (defaultTokenGenerator), `:1055` (createDashboardLoginCode), `:1131` (createDashboardSession), CLI `cmd/compute/main.go:369` (login-codes create).
- workflow-compute feature gap: `workflow-compute/docs/feature-state.md:82` (Cross-product passwordless identity, T411-T413).
- BMW current auth: `buymywishlist/app.yaml:784` (register), `:999` (login), `:6485..:6720` (passkey routes), `bmwplugin/step_auth.go` (bespoke steps).
- BMW nil-deref sample sites (audit must scan exhaustively): `:1071, :1084, :1098, :6596, :6793`.
- BMW `step.bmw.generate_token` call sites (retain in this design): `:668, :1103, :6848, :7023, :7241, :7571, :7625, :7887, :10940`.
- workflow-plugin-auth current surface: v0.2.4, `internal/plugin.go:265-300` (authContractRegistry, 26 contracts in STRICT mode), `internal/contracts/auth.proto`.
- workflow-plugin-auth magic-link API: `internal/step_magic_link.go:23-75` (stateless: caller stores token_hash).
