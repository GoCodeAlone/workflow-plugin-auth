# Admin Bootstrap + Passkey Upgrade — Design (2026-05-17)

## Goal

1. Restore BuyMyWishlist (BMW) signup/login (currently HTTP 500).
2. Add a reusable **admin bootstrap** flow to `workflow-plugin-auth`: declarative super-admin in config → CLI generates single-use HMAC-hashed one-time code → code redeems to session → session lets user enroll a passkey → bootstrap no longer needed except for break-glass recovery.
3. Migrate BMW off its bespoke `step.bmw.hash_password/verify_password/generate_token` onto the equivalent `workflow-plugin-auth` strict-proto steps so the plugin is the single source of auth truth.
4. Document a forward path for cross-product SSO (issuer, JWKS endpoint, refresh tokens) as a deferred follow-up; **not built in this design**.

## Out of scope (deferred)

- Cross-product SSO IDP surface (JWT issue/verify with shared issuer/audience, hosted JWKS, refresh tokens). Tracked as Phase II; separate design doc when needed. workflow-compute feature-state.md §"Cross-product passwordless identity" already tracks this as T411-T413.
- Replacing `workflow-compute`'s existing `wc_`-prefix dashboard login-codes implementation with the new step. Phase III follow-up; the new step is *modelled on* workflow-compute's pattern but workflow-compute keeps its bespoke path until separate migration.
- SSH-key signature binding on the bootstrap code. The user's mental model expected SSH-key involvement, but workflow-compute's existing pattern doesn't actually use SSH-keys — codes are random tokens delivered out-of-band. Same pattern adopted here; SSH-key signature can be added later if a concrete need surfaces.

## Top doubts (surfaced from self-challenge round)

1. **"SSH-key bootstrap" mismatch with reality.** User asked for SSH-key-based bootstrap; workflow-compute actually uses random HTTP one-time codes (no SSH-key crypto). Design follows the implementation reality, not the stated mental model. If the user actually wants SSH-key proof-of-possession layered on top, that becomes a Phase II addition (`step.auth_bootstrap_code_verify` accepts optional `ssh_signature` field validated against pubkey in config).
2. **Lazy alternative: just fix 5 nil-derefs + manually INSERT super_admin row.** Faster (≈1 hr) but ships no reuse. Design picks the reusable path because user explicitly asked for reusable + cross-product. Phase 1 of the plan still ships the hotfix as a standalone PR so access is restored within hours.
3. **strict-proto contract regen risk.** workflow-plugin-auth v0.2.4 onward uses strict-proto contracts (`internal/contracts/auth.proto`, `authContractRegistry` in `internal/plugin.go`). Adding 2 new step types requires: (a) proto messages added, (b) `make proto` regen, (c) registry entries with `CONTRACT_MODE_STRICT_PROTO`, (d) typed-step wrappers in `internal/typed.go`. Established pattern; low risk but non-trivial.

## Phases

### Phase 1 — BMW hotfix (independent, ship first)

Add `.found` guards before all 5 `.row.*` accesses in `buymywishlist/app.yaml`:

| Line | Step | Field accessed |
|---|---|---|
| 1071 | fetch_user.row | password_hash |
| 1084 | fetch_user.row | is_active |
| 1098 | fetch_user.row | id |
| 6596 | fetch_session.row | session_data |
| 6793 | find_credential.row | user_id |

For each: wrap dependent steps in conditional `{{ if .steps.<name>.found }}` blocks and return structured JSON error (401 / 404) when not found, never let template render against nil row. Verification: `docker compose up` + curl POST `/api/v1/auth/login` with (a) valid creds (b) unknown email (c) inactive user (d) valid passkey session (e) missing passkey session. All five must return well-formed JSON, not 500.

**Ships as one PR against buymywishlist.** Restores signup/login independently of plugin work.

### Phase 2 — `workflow-plugin-auth` v0.3.0 admin bootstrap

Add two new step types to `workflow-plugin-auth`:

- **`step.auth_admin_bootstrap_code_generate`** — input: `{user_id, ttl_seconds, generator_purpose}`. Generates 32-byte random code with `ab_` prefix (admin-bootstrap), HMAC-hashes via HKDF-derived key, stores `{id, hash, user_id, ttl, purpose, generated_at}` row in `auth_admin_bootstrap_codes` table. Returns plain-text code exactly once. Single-use semantics: row gets `consumed_at` set on first successful verify.
- **`step.auth_admin_bootstrap_code_verify`** — input: `{code, expected_user_id}`. Constant-time HMAC comparison against stored hash, TTL check, single-use check (rejects already-consumed rows). On success: marks consumed, returns `{user_id, granted_role, purpose}`. On failure: returns typed `BootstrapVerifyError` ({reason}).

Both steps gated by **declarative super-admin config** in `auth.credential` module (or new `auth.bootstrap` module if cleaner): the module config lists `super_admins: [{email, default_role}]` rows. Code generation rejects user_ids not in this list (so a compromised CLI session can't mint codes for arbitrary users).

CLI helper in plugin binary: `workflow-plugin-auth admin-bootstrap create --user-email <e> --ttl 10m` → generates code, prints to stdout. Operator delivers code out-of-band to user.

Migration adds `auth_admin_bootstrap_codes` table; ships as standard plugin migration (already-existing migration pattern, see `internal/module_credential.go` schema setup).

Proto contract additions: `BootstrapCodeGenerateInput/Output`, `BootstrapCodeVerifyInput/Output`, `BootstrapSuperAdminConfig`, `BootstrapVerifyError`. Mode `CONTRACT_MODE_STRICT_PROTO`. Registry entry in `internal/plugin.go:authContractRegistry`. Typed wrappers in `internal/typed.go`.

Tag as **v0.3.0** when shipped (minor bump: additive feature, no contract breakage).

### Phase 3 — BMW migration

Update BMW `app.yaml` to:

1. Replace `step.bmw.hash_password` calls with `step.auth_password_hash` (already in plugin).
2. Replace `step.bmw.verify_password` calls with `step.auth_password_verify` (already in plugin).
3. Replace `step.bmw.generate_token` with the JWT signing path the plugin already supports (or keep bespoke for now since SSO IDP is Phase II — call out as known limitation).
4. Add two new pipelines:
   - `POST /api/v1/admin/bootstrap-login` — calls `step.auth_admin_bootstrap_code_verify`, on success creates session, redirects to passkey-enrollment UI.
   - Admin UI affordance for "enroll passkey for my account" already exists (passkey routes work); just gate it on session role check.
5. Add `super_admins: [{email: "codingsloth@pm.me", default_role: "super_admin"}]` to BMW's `auth.credential` module config.
6. Document operator runbook: `wfctl plugin auth admin-bootstrap create --user-email codingsloth@pm.me --ttl 10m` → code → paste into `/admin/bootstrap-login` form → session → enroll passkey via existing UI → bootstrap retired.
7. Drop bespoke `bmwplugin/step_auth.go` once migration verified (keep as separate cleanup commit so revert is easy).

**Ships as one PR against buymywishlist after v0.3.0 plugin tag is published.**

### Phase II (Deferred)

- Cross-product SSO IDP: `auth.idp` module type with `issuer`, `audience`, `signing_key_id`, JWKS endpoint module that serves `/.well-known/jwks.json`, `step.auth_jwt_issue`, `step.auth_jwt_verify`, refresh-token issue/verify, key rotation hooks. Separate design doc.
- Migrate workflow-compute dashboard one-time codes onto `step.auth_admin_bootstrap_code_*`. Separate PR against workflow-compute.

## Assumptions (load-bearing)

1. workflow-plugin-auth v0.3.0 can ship without coupling to a new workflow engine version — current v0.51.6 pin is sufficient. *If false:* engine bump cascades.
2. Strict-proto contract additions are non-breaking for existing consumers (additive only, no signature changes to existing steps). *If false:* major bump + cascade through every consumer.
3. BMW currently passes wfctl validation against app.yaml after the 5 hotfix guards land. *If false:* the hotfix PR must include any related fixes surfaced by validation.
4. The pre-existing `.worktrees/bmw-prod-auth-passkey/` worktree contains compatible work that doesn't conflict with our changes. *If false:* operator resolves before Phase 3 lands.
5. `auth.credential` module currently has a database backend (SQLite or PostgreSQL via workflow-plugin-pgchannel) suitable for adding the new `auth_admin_bootstrap_codes` table. *If false:* schema location decision needed.
6. Single super-admin (codingsloth@pm.me) is acceptable for BMW initial bootstrap; multi-tenant super-admin config can stay as a list for forward compatibility but only one entry initially. *If false:* nothing — list shape already accommodates.
7. workflow-compute's existing `dashboard login-codes` flow is NOT in this PR's path; only Phase II migrates it. *If false:* scope creeps significantly; refuse and split.
8. Operator security model: bootstrap codes are delivered via secure channel (1Password, Signal, etc.) — the plugin is not responsible for delivery. *If false:* must add SMS/email magic-link delivery path, which is partially in plugin already but not wired to bootstrap.

## Rollback (per change class)

| Phase | Change class | Rollback |
|---|---|---|
| 1 | BMW YAML (no engine/migration/version-pin changes) | Revert PR; signup/login returns to broken-500 state (no worse than baseline). |
| 2 | workflow-plugin-auth v0.3.0 release (proto contract additions, schema migration, binary) | Untag v0.3.0; consumers stay on v0.2.4. New migration `auth_admin_bootstrap_codes` is additive — leaving the empty table behind is safe; drop separately if cleanup desired. |
| 3 | BMW migration onto plugin steps | Revert PR; BMW reverts to bespoke step.bmw.* steps. Bespoke step files preserved in same commit's separate cleanup commit so revert needs no recovery. Bootstrap codes table left in place (harmless empty table). |

## Verification gates

- **Phase 1:** Local `docker compose up` + manual curl of all 5 scenarios; user-visible signup/login working in browser. Phase 1 lands without CI changes beyond existing gates.
- **Phase 2:** `go test ./...` in plugin repo (≥95% on new files); `make proto` clean regen; CHANGELOG.md entry; v0.3.0 tag pushed; goreleaser CI green; manual smoke against a downstream consumer with a wfctl config that uses the new steps.
- **Phase 3:** Local `docker compose up` of BMW with v0.3.0 plugin pinned; manual signup → password login → admin bootstrap → passkey enroll → passkey login → bootstrap retired flow exercised end-to-end. `wfctl validate` green. Browser-test via Playwright (existing BMW Playwright suite covers auth routes).

## File touch surface (approximate)

| Repo | Files touched | Approx LOC |
|---|---|---|
| buymywishlist | app.yaml (Phase 1: 5 guards; Phase 3: ~80 lines auth replacement + bootstrap pipeline) | ~120 |
| workflow-plugin-auth | internal/contracts/auth.proto (+4 msg types); internal/plugin.go (+2 registry entries); internal/step_admin_bootstrap.go (NEW, ~250 LOC); internal/module_credential.go (super_admin list, ~30 LOC); internal/typed.go (~40 LOC); migrations/NNNN_admin_bootstrap_codes.sql (NEW); cmd/workflow-plugin-auth/admin_bootstrap_cli.go (NEW, ~80 LOC); CHANGELOG.md | ~500 |

## Sequencing & PR plan

- **PR-1** (BMW): Phase 1 hotfix. Independent. Merge first.
- **PR-2** (workflow-plugin-auth): Phase 2 v0.3.0. Depends on nothing.
- **PR-3** (buymywishlist): Phase 3 migration. Depends on PR-2 tag published.

PR-1 and PR-2 may be executed in parallel by separate implementers.

## Open questions left for the writing-plans phase

- Exact migration runner used by `workflow-plugin-auth` for schema bootstrap (likely already established; mirror existing pattern).
- Whether bootstrap CLI lives in plugin binary itself (`workflow-plugin-auth admin-bootstrap …`) or in `wfctl` (`wfctl plugin auth admin-bootstrap …`) — leaning binary-local since wfctl shouldn't grow per-plugin knowledge. **Decision deferred to plan phase.**
- Whether `auth.bootstrap` is a new module type or extends `auth.credential` — leaning new module type for clean responsibility split. **Decision deferred to plan phase.**

## References

- workflow-compute dashboard login codes: `workflow-compute/internal/server/auth.go:1413` (defaultTokenGenerator), `:1055` (createDashboardLoginCode), `:1131` (createDashboardSession), CLI `cmd/compute/main.go:369` (login-codes create).
- workflow-compute feature gap: `workflow-compute/docs/feature-state.md:82` (Cross-product passwordless identity, T411-T413).
- BMW current auth: `buymywishlist/app.yaml:784` (register), `:999` (login), `:6485..:6720` (passkey routes), `bmwplugin/step_auth.go` (bespoke steps).
- workflow-plugin-auth current surface: v0.2.4, `internal/plugin.go:265-300` (authContractRegistry, 26 contracts in STRICT mode), `internal/contracts/auth.proto`.
