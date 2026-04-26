# Auth OAuth Extraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract BMW's reusable authentication primitives into `workflow-plugin-auth`, release them publicly, and update BMW to consume the plugin.

**Architecture:** `workflow-plugin-auth` owns reusable cryptographic/provider steps, while BMW keeps app-specific persistence, tenant linking, and JWT policy in YAML. The plugin exposes stable `step.auth_*` outputs that match BMW's existing snake_case contracts so migration is mostly YAML step-type replacement.

**Tech Stack:** Go, Workflow external plugin SDK, `net/http/httptest`, `golang.org/x/crypto/bcrypt`, Workflow wftest, wfctl, BMW app YAML.

---

### Task 1: Add Password Hash And Verify Steps

**Files:**
- Create: `internal/step_password.go`
- Create: `internal/step_password_test.go`
- Modify: `internal/plugin.go`
- Modify: `internal/integration_test.go`

**Step 1: Write failing unit tests**

Add tests that instantiate `step.auth_password_hash` and `step.auth_password_verify` through `NewAuthPlugin().CreateStep`.

Test cases:
- Hash emits `hash` and does not echo `password`.
- Verify returns `valid: true` for a matching password/hash.
- Verify returns `valid: false` for a wrong password.
- Missing password or hash returns `valid: false` plus an `error` string.

Run: `GOWORK=off go test ./internal -run 'TestPassword' -count=1`

Expected: FAIL because the step types are unknown.

**Step 2: Implement minimal steps**

Create `internal/step_password.go`:

- `passwordHashStep.Execute` reads `current["password"]`.
- Hash with `bcrypt.GenerateFromPassword(..., bcrypt.DefaultCost)`.
- Output only `hash`.
- `passwordVerifyStep.Execute` reads `current["password"]` and `current["hash"]`.
- Use `bcrypt.CompareHashAndPassword`.
- Output `valid: true|false`.

Register:

- `step.auth_password_hash`
- `step.auth_password_verify`

**Step 3: Add integration coverage**

Add a wftest-style pipeline in `internal/integration_test.go` that records both password steps through plugin registration.

Run: `GOWORK=off go test ./internal -run 'TestPassword|TestWfTest' -count=1`

Expected: PASS.

**Step 4: Commit**

```bash
git add internal/step_password.go internal/step_password_test.go internal/plugin.go internal/integration_test.go
git commit -m "feat: add password hash auth steps"
```

### Task 2: Add Challenge Code Steps

**Files:**
- Create: `internal/step_challenge.go`
- Create: `internal/step_challenge_test.go`
- Modify: `internal/plugin.go`
- Modify: `internal/integration_test.go`

**Step 1: Write failing unit tests**

Test cases:
- `step.auth_challenge_generate` emits a six-digit `code`, `code_hash`, `destination`, and RFC3339 `expires_at`.
- Generate accepts `destination`, `signing_secret`, and optional `ttl_minutes`.
- Verify returns `valid: true` for the generated code/hash.
- Verify returns `valid: false` for wrong code.
- Verify returns `valid: false` for expired `expires_at`.

Run: `GOWORK=off go test ./internal -run 'TestChallenge' -count=1`

Expected: FAIL because the step types are unknown.

**Step 2: Implement steps**

Create `internal/step_challenge.go`:

- Generate a random six-digit code with `crypto/rand`.
- Hash `destination + ":" + code` using HMAC-SHA256 when `signing_secret` is set; otherwise SHA-256 for non-secret dev flows.
- Default TTL: 10 minutes.
- Verify recomputes the same hash and checks expiry if provided.
- Return errors in output, not panics, for missing inputs.

**Step 3: Add integration coverage**

Add wftest pipeline coverage for generate/verify registration.

Run: `GOWORK=off go test ./internal -run 'TestChallenge|TestWfTest' -count=1`

Expected: PASS.

**Step 4: Commit**

```bash
git add internal/step_challenge.go internal/step_challenge_test.go internal/plugin.go internal/integration_test.go
git commit -m "feat: add auth challenge steps"
```

### Task 3: Add Phone Normalization Step

**Files:**
- Create: `internal/step_phone.go`
- Create: `internal/step_phone_test.go`
- Modify: `internal/plugin.go`
- Modify: `internal/integration_test.go`

**Step 1: Write failing unit tests**

Test cases:
- `(555) 123-4567` normalizes to `+15551234567` with country `US`.
- `+15551234567` remains unchanged.
- Empty input returns `valid: false`.
- Too-short input returns `valid: false` and `error`.

Run: `GOWORK=off go test ./internal -run 'TestNormalizePhone' -count=1`

Expected: FAIL because the step type is unknown.

**Step 2: Implement minimal normalization**

Create `internal/step_phone.go`:

- Read `phone` from current input.
- Strip spaces, parentheses, dashes, and dots.
- Preserve `+` E.164 values with 8-15 digits.
- For 10 digits, prefix `+1`.
- For 11 digits starting with `1`, prefix `+`.
- Output `valid`, `phone_e164`, `country`, and `error` where applicable.

**Step 3: Add integration coverage**

Add wftest registration coverage for `step.auth_normalize_phone`.

Run: `GOWORK=off go test ./internal -run 'TestNormalizePhone|TestWfTest' -count=1`

Expected: PASS.

**Step 4: Commit**

```bash
git add internal/step_phone.go internal/step_phone_test.go internal/plugin.go internal/integration_test.go
git commit -m "feat: add auth phone normalization step"
```

### Task 4: Add Auth Method Policy Steps

**Files:**
- Create: `internal/step_methods_policy.go`
- Create: `internal/step_methods_policy_test.go`
- Modify: `internal/plugin.go`
- Modify: `internal/integration_test.go`

**Step 1: Write failing policy tests**

Test cases:
- Production disables password auth even when `password_auth_enabled` is true.
- Development enables password auth when explicitly configured.
- Passkey requires both `webauthn_rp_id` and `webauthn_origin`.
- Email code requires SMTP host and sender.
- SMS code requires routes enabled, SMS enabled, Verify service SID, and either auth token or API key/secret.
- OAuth providers include Google only when client ID, secret, redirect URL, and routes enabled are present.
- Missing/templated values containing `{{` are treated as absent.

Run: `GOWORK=off go test ./internal -run 'TestAuthMethodsPolicy' -count=1`

Expected: FAIL because the step type is unknown.

**Step 2: Implement policy and response steps**

Create `internal/step_methods_policy.go`:

- Port BMW policy behavior into generic names.
- Keep provider config data-driven through generic keys:
  `oauth_provider`, `google_oauth_client_id`, `google_oauth_client_secret`,
  `google_oauth_redirect_url`.
- Output:
  `passkey_enabled`, `email_code_enabled`, `sms_code_enabled`,
  `password_enabled`, `password_auth_enabled`, `totp_enabled`,
  `oauth_providers`, and `primary_method_count`.
- `step.auth_methods_response` mirrors the stable response shape.

**Step 3: Add audit step tests**

Add `step.auth_policy_audit` tests:

- Production with password auth requested reports `passed: false`.
- Production with `password_hash_count > 0` reports a violation.
- Development with password auth requested passes.

Run: `GOWORK=off go test ./internal -run 'TestAuthMethodsPolicy|TestAuthPolicyAudit' -count=1`

Expected: PASS.

**Step 4: Add integration coverage**

Add wftest registration coverage for:

- `step.auth_methods_policy`
- `step.auth_methods_response`
- `step.auth_policy_audit`

Run: `GOWORK=off go test ./internal -run 'TestAuthMethods|TestWfTest' -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/step_methods_policy.go internal/step_methods_policy_test.go internal/plugin.go internal/integration_test.go
git commit -m "feat: add auth methods policy steps"
```

### Task 5: Add OAuth Provider Steps

**Files:**
- Create: `internal/step_oauth.go`
- Create: `internal/step_oauth_test.go`
- Modify: `internal/plugin.go`
- Modify: `internal/integration_test.go`

**Step 1: Write failing OAuth tests**

Test cases:
- `step.auth_oauth_provider_config` returns Google provider metadata when configured.
- Incomplete Google config returns `available: false`.
- `step.auth_oauth_start` constrains empty return paths to `/auth/callback`.
- `step.auth_oauth_start` rejects absolute external `return_to` URLs.
- `step.auth_oauth_start` emits `state`, `authorization_url`, `expires_at`, and PKCE values when required.
- `step.auth_oauth_exchange` posts code, redirect URI, client credentials, and optional `code_verifier` to a test token endpoint.
- `step.auth_oauth_userinfo` fetches userinfo and outputs `provider`, `provider_subject`, `email`, `email_verified`, `name`, and `picture`.
- Non-2xx token/userinfo responses return clear errors.

Run: `GOWORK=off go test ./internal -run 'TestOAuth' -count=1`

Expected: FAIL because the step types are unknown.

**Step 2: Implement OAuth provider helpers**

Create `internal/step_oauth.go`:

- Add Google constants for auth/token/userinfo URLs and scopes.
- Allow tests/apps to override URLs via config keys:
  `google_oauth_authorization_url`, `google_oauth_token_url`,
  `google_oauth_userinfo_url`.
- Add generic helper functions for config values, provider normalization,
  random URL-safe tokens, PKCE challenge, same-site `return_to` normalization,
  and JSON response decoding with a 1 MiB body limit.

**Step 3: Implement OAuth steps**

Register:

- `step.auth_oauth_provider_config`
- `step.auth_oauth_start`
- `step.auth_oauth_exchange`
- `step.auth_oauth_userinfo`

Outputs must preserve BMW-compatible snake_case names.

Run: `GOWORK=off go test ./internal -run 'TestOAuth' -count=1`

Expected: PASS.

**Step 4: Add integration coverage**

Add wftest registration coverage for all OAuth step types.

Run: `GOWORK=off go test ./internal -run 'TestOAuth|TestWfTest' -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/step_oauth.go internal/step_oauth_test.go internal/plugin.go internal/integration_test.go
git commit -m "feat: add oauth auth steps"
```

### Task 6: Document And Validate Plugin Surface

**Files:**
- Create: `README.md`
- Modify: `plugin.json`
- Modify: `.github/workflows/ci.yml`

**Step 1: Document step contracts**

Create or update `README.md` with:

- Module and step type list.
- Password production warning.
- Challenge storage guidance.
- OAuth state storage guidance with atomic consume requirement.
- BMW migration example step-type mapping.

**Step 2: Ensure manifest advertises new steps**

Update `plugin.json` if it has an explicit step list. Keep the Go manifest and
JSON manifest aligned.

**Step 3: Verify plugin build and tests**

Run:

```bash
GOWORK=off go test ./... -count=1
GOWORK=off go build ./cmd/workflow-plugin-auth
```

Expected:

- Tests pass.
- `go build` exits 0.

**Step 4: Runtime plugin load smoke test**

Use the repo's existing wftest integration or a minimal Workflow plugin SDK
execution test to instantiate every advertised step type through `NewAuthPlugin`.

Run: `GOWORK=off go test ./internal -run 'TestPluginManifest|TestWfTest' -count=1`

Expected: PASS and all advertised step types instantiate.

**Step 5: Commit**

```bash
git add README.md plugin.json .github/workflows/ci.yml internal
git commit -m "docs: document auth plugin extraction surface"
```

### Task 7: Prepare Public Plugin PR

**Files:**
- Modify only files changed by Tasks 1-6.

**Step 1: Run final verification**

Run:

```bash
GOWORK=off go test ./... -count=1
GOWORK=off go build ./cmd/workflow-plugin-auth
git diff --check
```

Expected:

- Tests pass.
- Build exits 0.
- `git diff --check` emits no output.

**Step 2: Push and open PR**

```bash
git push -u origin feat/auth-oauth-extraction
gh pr create --repo GoCodeAlone/workflow-plugin-auth --base main --head feat/auth-oauth-extraction
```

**Step 3: Start PR monitoring**

Use `superpowers:pr-monitoring` for the plugin PR. Do not auto-merge. Report
ready for admin merge only after CI is green and review comments are handled.

### Task 8: Release Plugin And Update BMW

**Files:**
- In `workflow-plugin-auth`: release metadata only, if needed by repo release process.
- In BMW: `app.yaml`, `Dockerfile.prebuilt` or plugin install path files, `go.mod`, `go.sum`, `docs/DEPLOYMENT.md`, relevant tests.

**Step 1: Release plugin**

After the plugin PR is admin-merged, follow the repo release process:

```bash
git tag v<next>
git push origin v<next>
```

Expected: GitHub release workflow publishes `workflow-plugin-auth` assets.

**Step 2: Create BMW migration branch**

Use an isolated BMW worktree branch, for example:

```bash
git worktree add /Users/jon/workspace/_worktrees/bmw-auth-plugin-migration -b chore/use-workflow-plugin-auth main
```

Expected: new clean BMW worktree.

**Step 3: Replace BMW-local step types**

Update BMW YAML:

- `step.bmw.auth_policy` -> `step.auth_methods_policy`
- `step.bmw.auth_methods_response` -> `step.auth_methods_response`
- `step.bmw.oauth_provider_config` -> `step.auth_oauth_provider_config`
- `step.bmw.oauth_start` -> `step.auth_oauth_start`
- `step.bmw.oauth_exchange` -> `step.auth_oauth_exchange`
- `step.bmw.oauth_userinfo` -> `step.auth_oauth_userinfo`
- `step.bmw.auth_challenge_generate` -> `step.auth_challenge_generate`
- `step.bmw.auth_challenge_verify` -> `step.auth_challenge_verify`
- `step.bmw.normalize_phone` -> `step.auth_normalize_phone`

Keep BMW SQL and JWT issuance unchanged.

**Step 4: Remove BMW-local duplicate code only after tests pass**

Delete BMW-local step implementations that are no longer referenced:

- `bmwplugin/step_oauth.go`
- matching portions of `bmwplugin/step_auth_policy.go`
- matching challenge/phone code

Do not remove password/JWT code unless BMW no longer references it.

**Step 5: Verify BMW migration**

Run:

```bash
GOWORK=off go test ./bmwplugin/... -count=1
wfctl validate --skip-unknown-types app.yaml infra.yaml
cd ui && npm run build
git diff --check
```

Expected:

- BMW plugin tests pass.
- wfctl validates both configs with only known warnings.
- UI build exits 0.
- No whitespace errors.

**Step 6: Push BMW PR and monitor**

Open a BMW PR and use `superpowers:pr-monitoring`. Do not auto-merge. Admin
merge only after CI is green and review comments are handled.
