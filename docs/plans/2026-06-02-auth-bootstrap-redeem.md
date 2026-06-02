# Durable First-Run Admin Bootstrap — Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Add two stateless, engine-mediated steps to workflow-plugin-auth — `step.auth_bootstrap_redeem` (count-gated first-run admin code redemption) and `step.auth_jwt_issue` (HS256 session mint) — then prove the full durable-bootstrap → enrol-passkey → bootstrap-auto-closes flow in a new workflow-scenarios admin stack.

**Architecture:** Both steps are stateless (no DB/socket); the consumer pipeline owns persistence (Postgres via `database.workflow`) + routing + session gating (engine `step.auth_validate`). Bootstrap is OPEN ⟺ zero admin credentials exist. Session mint via `step.auth_jwt_issue`, validated by the engine `auth.jwt` module sharing the HS256 secret.

**Tech Stack:** Go 1.26; workflow SDK (`plugin/external/sdk`); proto STRICT_PROTO contracts (`internal/contracts/auth.proto`); `golang-jwt/jwt/v5`; `google/uuid`; workflow engine (`database.workflow`, `auth.jwt`, `step.auth_validate`, `step.token_revoke`, `step.rate_limit`); docker-compose + Postgres; Playwright (CDP virtual authenticator); playwright-cli.

**Base branch:** main (workflow-plugin-auth); main (workflow-registry); main (workflow-scenarios)

**Design:** `docs/plans/2026-06-02-auth-bootstrap-redeem-design.md` (rev 4, adversarial PASS). ADR-0001, ADR-0002.

---

## Scope Manifest

**PR Count:** 3
**Tasks:** 11
**Estimated Lines of Change:** ~900 (informational)

**Out of scope:**
- Migrating gocodealone-multisite's bespoke `admin_bootstrap.go` onto the new steps (tracked follow-up issue, filed post-merge).
- Full IDP surface: JWKS endpoint, refresh tokens, asymmetric/ES256, `auth.idp` module, key rotation (Phase II, ADR-0002).
- Plugin-side credential persistence / DB ownership (stays consumer-pipeline-owned, V-B3).

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | feat: bootstrap-redeem + jwt-issue steps (v0.3.0) | Task 1, Task 2, Task 3, Task 4, Task 5, Task 6 | feat/auth-bootstrap-redeem-2026-06-02 |
| 2 | chore: registry manifest v0.3.0 (31 steps) | Task 7 | feat/auth-manifest-v0.3.0 (workflow-registry) |
| 3 | test: scenario 101 auth admin bootstrap stack | Task 8, Task 9, Task 10, Task 11 | feat/scenario-101-auth-admin-bootstrap (workflow-scenarios) |

**Status:** Locked 2026-06-02T06:28:06Z

---

## PR 1 — workflow-plugin-auth: two new steps + v0.3.0

Work in the existing worktree branch `feat/auth-bootstrap-redeem-2026-06-02`
(`/Users/jon/workspace/workflow-plugin-auth/.worktrees/auth-bootstrap`).
Build/test with `GOWORK=off`.

### Task 1: Proto messages for both steps

**Files:**
- Modify: `internal/contracts/auth.proto` (append message-sets)
- Regenerate: `internal/contracts/auth.pb.go`

**Step 1:** Append to `internal/contracts/auth.proto` (before EOF, package `workflow.plugins.auth.v1`):

```proto
// --- Bootstrap redeem (step.auth_bootstrap_redeem) ---
message BootstrapRedeemConfig {
  string super_admin_email = 1;
  string super_admin_role  = 2;   // output label; default "super_admin" applied in Go
  string code_env          = 3;   // env var NAME; default "AUTH_BOOTSTRAP_CODE" applied in Go
}
message BootstrapRedeemInput {
  string code                 = 1;
  // existing_admin_count arrives via the dynamic pipeline context, not a typed field,
  // because db_query/step.set emit it as a JSON number/string; read from `current`.
  string existing_admin_count = 2; // accepted as string|number at runtime; coerced in Go
}
message BootstrapRedeemOutput {
  bool   redeemed = 1;
  string email    = 2;
  string role     = 3;
  string reason    = 4;  // "" | "bootstrap_closed" | "invalid_code" | "not_configured"
  string error    = 100;
}

// --- JWT issue (step.auth_jwt_issue) ---
message JWTIssueConfig {
  string secret_env  = 1;  // env var NAME; default "AUTH_JWT_SECRET"
  string issuer      = 2;  // default "workflow-plugin-auth"
  int64  ttl_seconds = 3;  // default 3600
}
message JWTIssueInput {
  string                  subject = 1;
  google.protobuf.Struct  claims  = 2;
}
message JWTIssueOutput {
  string token      = 1;
  string expires_at = 2;  // RFC3339
  string error      = 100;
}
```

**Step 2:** Regenerate. No Makefile/buf target; the existing header shows `protoc-gen-go v1.36.11`. Run:
```bash
cd internal/contracts
protoc -I . -I "$(brew --prefix protobuf 2>/dev/null)/include" \
  --go_out=. --go_opt=paths=source_relative auth.proto
```
The `-I .../include` resolves the well-known `google/protobuf/struct.proto` import (already imported at `auth.proto:7`; F6). If `protoc`/`protoc-gen-go` absent: `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11` + `brew install protobuf`, then re-run. Verify the new messages appear in `auth.pb.go`.
Expected: `auth.pb.go` contains `type BootstrapRedeemInput struct` and `type JWTIssueOutput struct`.

**Step 3:** Verify compile: `GOWORK=off go build ./...` → exit 0.

**Step 4:** Commit.
```bash
git add internal/contracts/auth.proto internal/contracts/auth.pb.go
git commit -m "feat(auth): proto contracts for bootstrap_redeem + jwt_issue steps"
```

### Task 2: `step.auth_bootstrap_redeem` (TDD)

**Files:**
- Create: `internal/step_bootstrap.go`
- Create: `internal/step_bootstrap_test.go`

> **Test idiom (plan-cycle F5):** call `Execute` directly with the real signature — do NOT use a generic helper. The signature (per `internal/step_credential_test.go`) is `Execute(context.Context, map[string]any, map[string]map[string]any, current, map[string]any, map[string]any) (*sdk.StepResult, error)`. Pattern:
> ```go
> res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
> if err != nil { t.Fatalf("execute: %v", err) }
> out := res.Output  // map[string]any
> ```
> Replace every `mustExec(t, s, current)` below with this 3-line idiom inline (assign `out := res.Output`).

**Step 1 — failing test** (`internal/step_bootstrap_test.go`):

```go
package internal

import "testing"

func TestBootstrapRedeem_OpenAndValid(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	out := mustExec(t, s, map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": float64(0)})
	if out["redeemed"] != true {
		t.Fatalf("want redeemed=true, got %v (reason=%v)", out["redeemed"], out["reason"])
	}
	if out["email"] != "admin@example.com" || out["role"] != "super_admin" {
		t.Fatalf("bad principal: %v / %v", out["email"], out["role"])
	}
}

func TestBootstrapRedeem_ClosedWhenCredentialsExist(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	// count > 0 → closed, even with the correct code
	out := mustExec(t, s, map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": float64(1)})
	if out["redeemed"] != false || out["reason"] != "bootstrap_closed" {
		t.Fatalf("want closed, got redeemed=%v reason=%v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_DefaultDenyMissingCount(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	out := mustExec(t, s, map[string]any{"code": "super-secret-bootstrap-code-001"}) // no count
	if out["redeemed"] != false || out["reason"] != "bootstrap_closed" {
		t.Fatalf("want default-deny closed, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_InvalidCode(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	out := mustExec(t, s, map[string]any{"code": "wrong", "existing_admin_count": float64(0)})
	if out["redeemed"] != false || out["reason"] != "invalid_code" {
		t.Fatalf("want invalid_code, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_NotConfiguredShortCode(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "short") // < 16
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	out := mustExec(t, s, map[string]any{"code": "short", "existing_admin_count": float64(0)})
	if out["redeemed"] != false || out["reason"] != "not_configured" {
		t.Fatalf("want not_configured, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_CountCoercion(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "a@b.com"})
	for _, c := range []any{0, int64(0), float64(0), "0"} {
		out := mustExec(t, s, map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": c})
		if out["redeemed"] != true {
			t.Fatalf("count %T(%v) should coerce to 0 → open; got reason=%v", c, c, out["reason"])
		}
	}
}

// Use the inline idiom from the note above (res, err := s.Execute(context.Background(), nil, nil, current, nil, nil); out := res.Output).
// `mustExec(t, s, current)` in these snippets is shorthand for that 3-line block — expand it inline; do NOT define a generic-interface helper (it will not satisfy the concrete *sdk.StepResult return type).
```

**Step 2:** Run `GOWORK=off go test ./internal/ -run TestBootstrapRedeem -v` → FAIL (undefined `newBootstrapRedeemStep`).

**Step 3 — implementation** (`internal/step_bootstrap.go`):

```go
package internal

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"strconv"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

const bootstrapMinCodeLength = 16

type bootstrapRedeemStep struct {
	name            string
	superAdminEmail string
	superAdminRole  string
	codeEnv         string
}

func newBootstrapRedeemStep(name string, config map[string]any) *bootstrapRedeemStep {
	role := configString(config, "super_admin_role")
	if role == "" {
		role = "super_admin"
	}
	codeEnv := configString(config, "code_env")
	if codeEnv == "" {
		codeEnv = "AUTH_BOOTSTRAP_CODE"
	}
	return &bootstrapRedeemStep{
		name:            name,
		superAdminEmail: configString(config, "super_admin_email"),
		superAdminRole:  role,
		codeEnv:         codeEnv,
	}
}

func (s *bootstrapRedeemStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	envCode := strings.TrimSpace(os.Getenv(s.codeEnv))
	if len(envCode) < bootstrapMinCodeLength {
		return deny("not_configured"), nil
	}
	count, ok := coerceCount(current["existing_admin_count"])
	if !ok || count != 0 {
		return deny("bootstrap_closed"), nil // default-deny on missing/uncoercible/>0
	}
	code, _ := current["code"].(string)
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(envCode)) != 1 {
		return deny("invalid_code"), nil
	}
	return &sdk.StepResult{Output: map[string]any{
		"redeemed": true, "email": s.superAdminEmail, "role": s.superAdminRole, "reason": "",
	}}, nil
}

func deny(reason string) *sdk.StepResult {
	return &sdk.StepResult{Output: map[string]any{"redeemed": false, "reason": reason}}
}

// coerceCount returns (count, true) only for an unambiguous integer 0..N.
func coerceCount(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

var _ = fmt.Sprintf // keep import if unused after edits
```
> Drop the `fmt` import if unused. `configString` already exists in `module_credential.go`.

**Step 4:** Run `GOWORK=off go test ./internal/ -run TestBootstrapRedeem -v` → PASS (all 6).

**Step 5:** Commit.
```bash
git add internal/step_bootstrap.go internal/step_bootstrap_test.go
git commit -m "feat(auth): step.auth_bootstrap_redeem — count-gated first-run redemption"
```

### Task 3: `step.auth_jwt_issue` (TDD)

**Files:**
- Create: `internal/step_jwt_issue.go`
- Create: `internal/step_jwt_issue_test.go`
- Modify: `go.mod`/`go.sum` (promote direct deps)

**Step 1:** Promote deps:
```bash
GOWORK=off go get github.com/golang-jwt/jwt/v5@v5.3.1
GOWORK=off go get github.com/google/uuid@v1.6.0
```

**Step 2 — failing test** (`internal/step_jwt_issue_test.go`): assert (a) a token is produced for a ≥32-char secret; (b) it round-trips via `jwt.Parse` with the same secret and carries `sub`==subject + caller claim `roles`; (c) **caller cannot override `sub`** — passing `claims:{sub:"evil"}` still yields `sub`==subject (V-B8); (d) secret `<32` → `{error}` non-empty, no token.

```go
package internal

import (
	"testing"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestJWTIssue_SignsAndStandardClaimsWin(t *testing.T) {
	secret := "this-is-a-32-byte-minimum-secret-xx" // >=32
	t.Setenv("AUTH_JWT_SECRET", secret)
	s := newJWTIssueStep("t", map[string]any{"issuer": "wf-test", "ttl_seconds": int64(60)})
	out := mustExecJWT(t, s, map[string]any{
		"subject": "admin@example.com",
		"claims":  map[string]any{"roles": []any{"super_admin"}, "sub": "evil", "iss": "evil"},
	})
	tokStr, _ := out["token"].(string)
	if tokStr == "" {
		t.Fatalf("no token; error=%v", out["error"])
	}
	tok, err := jwt.Parse(tokStr, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil || !tok.Valid {
		t.Fatalf("token did not validate with shared secret: %v", err)
	}
	c := tok.Claims.(jwt.MapClaims)
	if c["sub"] != "admin@example.com" {
		t.Fatalf("caller overrode sub: %v (V-B8 violated)", c["sub"])
	}
	if c["iss"] != "wf-test" {
		t.Fatalf("caller overrode iss: %v", c["iss"])
	}
}

func TestJWTIssue_RejectsShortSecret(t *testing.T) {
	t.Setenv("AUTH_JWT_SECRET", "tooshort")
	s := newJWTIssueStep("t", nil)
	out := mustExecJWT(t, s, map[string]any{"subject": "x"})
	if out["token"] != "" && out["token"] != nil {
		t.Fatalf("expected no token for short secret")
	}
	if out["error"] == "" || out["error"] == nil {
		t.Fatalf("expected error for short secret")
	}
}
```
> `mustExecJWT` uses the same `sdk.StepResult` unwrap idiom as Task 2.

**Step 3 — implementation** (`internal/step_jwt_issue.go`):

```go
package internal

import (
	"context"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

const jwtMinSecretLength = 32

type jwtIssueStep struct {
	name      string
	secretEnv string
	issuer    string
	ttl       time.Duration
}

func newJWTIssueStep(name string, config map[string]any) *jwtIssueStep {
	secretEnv := configString(config, "secret_env")
	if secretEnv == "" {
		secretEnv = "AUTH_JWT_SECRET"
	}
	issuer := configString(config, "issuer")
	if issuer == "" {
		issuer = "workflow-plugin-auth"
	}
	ttl := 3600 * time.Second
	if n, ok := coerceCount(config["ttl_seconds"]); ok && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	return &jwtIssueStep{name: name, secretEnv: secretEnv, issuer: issuer, ttl: ttl}
}

func (s *jwtIssueStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	secret := strings.TrimSpace(os.Getenv(s.secretEnv))
	if len(secret) < jwtMinSecretLength {
		return &sdk.StepResult{Output: map[string]any{"error": "signing secret not configured"}}, nil
	}
	subject, _ := current["subject"].(string)

	claims := jwt.MapClaims{}
	// caller claims FIRST...
	if caller, ok := current["claims"].(map[string]any); ok {
		for k, v := range caller {
			claims[k] = v
		}
	}
	// ...then standard claims ALWAYS overwrite (V-B8: caller cannot override).
	now := time.Now()
	exp := now.Add(s.ttl)
	claims["sub"] = subject
	claims["iat"] = now.Unix()
	claims["exp"] = exp.Unix()
	claims["iss"] = s.issuer
	claims["jti"] = uuid.NewString()

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": "failed to sign token"}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{
		"token": signed, "expires_at": exp.UTC().Format(time.RFC3339),
	}}, nil
}
```
> The typed-step path (Task 4) passes `claims` as a `*structpb.Struct`; the map path passes `map[string]any`. Handle both in `current["claims"]` (add a `*structpb.Struct` → `.AsMap()` branch). Add a test case for the structpb shape.

**Step 4:** Run `GOWORK=off go test ./internal/ -run TestJWTIssue -v` → PASS.

**Step 5:** Commit.
```bash
git add internal/step_jwt_issue.go internal/step_jwt_issue_test.go go.mod go.sum
git commit -m "feat(auth): step.auth_jwt_issue — HS256 session mint (V-B8 reserved-claim guard)"
```

### Task 4: Wire both steps into the plugin registry + contracts

**Files:**
- Modify: `internal/plugin.go` (allStepTypes, CreateStep, CreateTypedStep, authContractRegistry)
- Modify: `internal/plugin_contracts_test.go` / `internal/contract_smoke_test.go` (extend coverage if they enumerate steps)

**Step 1:** Add to `allStepTypes`: `"step.auth_bootstrap_redeem"`, `"step.auth_jwt_issue"`.

**Step 2:** Add `CreateStep` cases:
```go
case "step.auth_bootstrap_redeem":
	return newBootstrapRedeemStep(name, config), nil
case "step.auth_jwt_issue":
	return newJWTIssueStep(name, config), nil
```

**Step 3:** Add `CreateTypedStep` cases mirroring the existing `typedLegacyStep` pattern:
```go
case "step.auth_bootstrap_redeem":
	return sdk.NewTypedStepFactory(typeName, &contracts.BootstrapRedeemConfig{}, &contracts.BootstrapRedeemInput{}, typedLegacyStep[*contracts.BootstrapRedeemConfig, *contracts.BootstrapRedeemInput, *contracts.BootstrapRedeemOutput](func(name string, config map[string]any) sdk.StepInstance {
		return newBootstrapRedeemStep(name, config)
	}, &contracts.BootstrapRedeemOutput{})).CreateTypedStep(typeName, name, config)
case "step.auth_jwt_issue":
	return sdk.NewTypedStepFactory(typeName, &contracts.JWTIssueConfig{}, &contracts.JWTIssueInput{}, typedLegacyStep[*contracts.JWTIssueConfig, *contracts.JWTIssueInput, *contracts.JWTIssueOutput](func(name string, config map[string]any) sdk.StepInstance {
		return newJWTIssueStep(name, config)
	}, &contracts.JWTIssueOutput{})).CreateTypedStep(typeName, name, config)
```

**Step 4:** Add to `authContractRegistry.Contracts`:
```go
stepContract("step.auth_bootstrap_redeem", "BootstrapRedeemConfig", "BootstrapRedeemInput", "BootstrapRedeemOutput"),
stepContract("step.auth_jwt_issue", "JWTIssueConfig", "JWTIssueInput", "JWTIssueOutput"),
```

**Step 5 — verify contracts** (change class: plugin/extension → load + exercise):
```bash
GOWORK=off go test ./internal/ -run 'Contract|Smoke|StrictProto' -v
GOWORK=off go build ./...
```
Expected: PASS; build exit 0. The strict-proto smoke test must accept the 2 new steps (31 total).

**Step 6:** Commit.
```bash
git add internal/plugin.go internal/*_test.go
git commit -m "feat(auth): register bootstrap_redeem + jwt_issue in step/typed/contract registries"
```

### Task 5: Manifest + SPEC + README + full verification

**Files:**
- Modify: `plugin.json` (stepTypes + capabilities.stepTypes → 31)
- Modify: `SPEC.md` (§I step list; §V add V-B1..V-B8; §T add T-AUTH-14/15 rows)
- Modify: `README.md` (Step Types list + a "First-run admin bootstrap" subsection)

**Step 1:** Add both step types to `plugin.json` `stepTypes` AND `capabilities.stepTypes` (keep arrays sorted-ish consistent with current order; append).

**Step 2:** SPEC.md — add the two steps to §I Step types; add invariants V-B1..V-B8 (copy from the design §V); add §T rows:
```
| T-AUTH-14 step.auth_bootstrap_redeem (count-gated) | ✅ | internal/step_bootstrap.go + test |
| T-AUTH-15 step.auth_jwt_issue (HS256 mint) | ✅ | internal/step_jwt_issue.go + test |
```

**Step 3:** README — add both steps to the Step Types list + a short subsection describing the bootstrap→passkey flow and the `AUTH_BOOTSTRAP_CODE`/`AUTH_JWT_SECRET` env vars (≥16 / ≥32 char requirements).

**Step 4 — full verification gate** (Go-repo change class):
```bash
GOWORK=off go test -race ./... 2>&1 | tail -20         # all green
GOWORK=off go build ./...                               # exit 0
GOWORK=off golangci-lint run --new-from-rev=origin/main ./...   # exit 0
```
Expected: tests green, build clean, lint 0 issues.

**Step 5:** Commit.
```bash
git add plugin.json SPEC.md README.md
git commit -m "docs(auth): manifest(31) + SPEC §V/§T + README for bootstrap+jwt-issue steps"
```

### Task 6: Open PR 1, monitor, merge, tag v0.3.0

**Rollback:** revert PR; do NOT advance the v0.3.0 tag; consumers on v0.2.12 unaffected (steps absent).

**Step 1:** Push branch; open PR against `main` with body summarizing the 2 steps + design/ADR links + the §Cycle resolutions. `gh pr create`.

**Step 2:** Monitor CI (autodev:pr-monitoring) + Copilot review. Address findings. Bash poll-loop for CI (per `feedback_ci_wait_use_bash_poll_loop`).

**Step 3:** Pre-tag check: `git ls-remote --tags origin | grep -c 'v0.3.0$'` → expect 0.

**Step 4:** On CI green + Copilot clear → admin-merge. Then tag:
```bash
git checkout main && git pull
git tag v0.3.0 && git push origin v0.3.0
```
Expected: release.yml builds v0.3.0 cross-platform; GitHub release Latest. Verify `gh release view v0.3.0`.

---

## PR 2 — workflow-registry: manifest v0.3.0 (31 steps)

### Task 7: Rebuild the auth manifest to v0.3.0 with all 31 steps

**Repo:** `/Users/jon/workspace/workflow-registry` (branch `feat/auth-manifest-v0.3.0` off main).
**Depends on:** PR 1 merged + v0.3.0 released (downloads URLs reference v0.3.0).

**Files:**
- Modify: `v1/plugins/workflow-plugin-auth/manifest.json`
- Modify: `v1/index.json` (auth entry version + minEngineVersion)

**Step 1:** Pre-edit existence check: `ls v1/plugins/workflow-plugin-auth/manifest.json` (exists at v0.2.7, 25 steps).

**Step 2:** Set `version` → `0.3.0`; `minEngineVersion` → `0.57.2` (align to plugin.json). This registry manifest uses **`capabilities.stepTypes`** (there is NO top-level `stepTypes` field — F2). Replace `capabilities.stepTypes` with the full 31-step list (the 29 from the merged `plugin.json` `capabilities.stepTypes` + `step.auth_bootstrap_redeem` + `step.auth_jwt_issue`); also update `capabilities.moduleTypes` if unchanged (still `auth.credential`). Update `downloads` URLs to the `v0.3.0` release assets.

**Step 3:** Update `v1/index.json` auth entry: `version` 0.3.0, `minEngineVersion` 0.57.2.

**Step 4 — verify** (manifest/config-validation class): `python3 -c "import json; m=json.load(open('v1/plugins/workflow-plugin-auth/manifest.json')); assert m['version']=='0.3.0'; st=m['capabilities']['stepTypes']; assert len(st)==31, len(st); assert 'step.auth_bootstrap_redeem' in st and 'step.auth_jwt_issue' in st; print('ok', len(st))"`. If the repo has a manifest-lint/CI script, run it. Expected: `ok 31`.

**Step 5:** Commit + PR + monitor + admin-merge on green.
```bash
git add v1/plugins/workflow-plugin-auth/manifest.json v1/index.json
git commit -m "chore(auth): manifest v0.3.0 — bootstrap_redeem + jwt_issue (31 steps)"
```
**Rollback:** revert manifest PR; `verify-capabilities` reverts to the prior step set.

---

## PR 3 — workflow-scenarios: scenario 101 admin bootstrap stack

**Repo:** `/Users/jon/workspace/workflow-scenarios` (branch `feat/scenario-101-auth-admin-bootstrap` off main).
**Depends on:** PR 1 merged (builds the plugin from the sibling checkout at the v0.3.0 source).
**Reference template:** `scenarios/92-infra-admin-demo/` (docker-compose + seed + run.sh) and `scenarios/20-auth-service/` (auth.jwt module + routes).

### Task 8: Scenario scaffold — config, compose, seed

**Files (all under `scenarios/101-auth-admin-bootstrap/`):**
- Create: `scenario.yaml`, `README.md`
- Create: `config/app.yaml`
- Create: `docker-compose.yml`
- Create: `seed/seed.sh`

**Step 1:** `scenario.yaml` — id `101-auth-admin-bootstrap`, category C, components `[workflow, workflow-plugin-auth, auth.jwt, database.workflow(postgres)]`, status `testable`, tags `[admin, auth, passkey, bootstrap, playwright]`, description of the durable first-run flow.

**Step 2:** `config/app.yaml` — the engine config. Modules:
- `server` (`http.server`, `:8080`), `router` (`http.router`).
- `jwtauth` (`auth.jwt`, `secret: ${AUTH_JWT_SECRET}`, `tokenExpiry: "1h"`, `issuer: workflow-plugin-auth`) — the AuthProvider the gate validates against.
- `authcred` (`auth.credential`, `rp_id`/`origin` for WebAuthn).
- `db` (`database.workflow`, `driver: postgres`, `dsn: ${DATABASE_URL}`).
- Routes + pipelines (per design §I consumer wiring):
  - `GET /admin/bootstrap/status` → db_query count_creds → json_response `{open: count==0}`.
  - `POST /admin/bootstrap/redeem` → request_parse → db_query count_creds → set existing_admin_count → `step.auth_bootstrap_redeem` → conditional: redeemed → db_exec INSERT user ON CONFLICT DO NOTHING → `step.auth_jwt_issue` → json_response `{token}`; else 403 `{reason}`. Wrap the route with `step.rate_limit` (5/min/IP).
  - `POST /admin/credentials/passkey/register/{begin,finish}` → `step.request_parse` named `parse_auth` with `parse_headers: [Authorization]` → `step.auth_validate {auth_module: jwtauth, token_source: steps.parse_auth.headers.Authorization}` (F1: NOT a leading-dot path — leading-dot resolves to nil and 401s always) → existing `step.auth_passkey_begin_register`/`finish_register` → db_exec INSERT credential(kind='passkey') on finish.
  > **Template: copy the auth-gate wiring verbatim from `scenarios/90-admin-tailnet-demo/config/app.yaml`** (it uses `auth.jwt` + a `parse_auth` request_parse + `step.auth_validate token_source: steps.parse_auth.headers.Authorization` on every protected route — the exact pattern this scenario needs). Every protected route below uses the same `parse_auth`→`auth_validate` prefix.
  - `POST /admin/login/passkey/{begin,finish}` → `step.auth_passkey_begin_login`/`finish_login` (lookup credential by db_query) → `step.auth_jwt_issue` → `{token}`.
  - `POST /admin/logout` → `parse_auth` → `step.auth_validate` → `step.token_revoke`.
  - `GET /healthz` → json_response 200.
> Cross-check every step/module type name against `scenarios/90-admin-tailnet-demo/config/app.yaml` (auth gate) + `20-auth-service` (auth.jwt) + `92-infra-admin-demo` (db).

**Step 3:** `docker-compose.yml` — **image-bake pattern (F3/option), copy scenario 92's structure exactly**: services `postgres` (`postgres:16-alpine`, env POSTGRES_*, healthcheck) + `app` (`image: auth-admin:scenario-101` built by seed.sh, env `AUTH_BOOTSTRAP_CODE`/`AUTH_JWT_SECRET`/`DATABASE_URL`, `depends_on: postgres: condition: service_healthy`), port `18101:8080`. Engine reads `plugin_dir: /data/plugins` (baked into the image, NOT volume-mounted).

**Step 4:** `seed/seed.sh` — **mirror `scenarios/92-infra-admin-demo/seed/seed.sh` exactly** (image-bake), with these deltas: (a) `docker compose up -d postgres`; wait healthy; (b) create tables `users(email PK, role)` + `credentials(id, user_email, kind, public_key, device_name, created_at, last_used_at)` (psql against the postgres service); (c) **cross-compile** the engine server AND the auth plugin for the container (F3): `(cd $WORKFLOW_REPO && GOWORK=off GOOS=linux GOARCH=amd64 go build -o $BUILD_DIR/server ./cmd/server)` and `(cd ../../workflow-plugin-auth && GOWORK=off GOOS=linux GOARCH=amd64 go build -o $BUILD_DIR/plugins/workflow-plugin-auth/workflow-plugin-auth ./cmd/workflow-plugin-auth)` + `cp ../../workflow-plugin-auth/plugin.json $BUILD_DIR/plugins/workflow-plugin-auth/plugin.json`; (d) Dockerfile `COPY server /usr/local/bin/server` + `COPY plugins/ /data/plugins/`; `docker build -t auth-admin:scenario-101 $BUILD_DIR`; (e) `docker compose up -d`; wait `/healthz` 200.

**Step 5 — verify:** `bash -n seed/seed.sh` (syntax); `wfctl validate --plugin-manifest ../../workflow-plugin-auth/plugin.json config/app.yaml` → pass (F4: the `--plugin-manifest` flag resolves the plugin-provided `auth.credential` + `step.auth_*` types; entry-point `http.server` present).

**Step 6:** Commit.
```bash
git add scenarios/101-auth-admin-bootstrap/
git commit -m "test(scenario-101): admin bootstrap stack scaffold (config + compose + seed)"
```

### Task 9: Deterministic curl smoke (`test/run.sh`)

**Files:** Create `scenarios/101-auth-admin-bootstrap/test/run.sh` (PASS:/FAIL: prefixes, mirror scenario 92's harness).

**Assertions (change class: multi-component boundary + API endpoint):**
1. `GET /healthz` → 200.
2. fresh DB → `GET /admin/bootstrap/status` → `open:true`.
3. `POST /admin/bootstrap/redeem` wrong code → 403, body `reason:"invalid_code"`.
4. correct code (env `AUTH_BOOTSTRAP_CODE`) → 200, body has non-empty `token`; super-admin row exists (`psql ... SELECT count(*) FROM users` → 1).
5. authenticated `POST /admin/credentials/passkey/register/begin` (Bearer token from step 4) → 200 with a WebAuthn challenge; **no Bearer → 401** (proves `step.auth_validate` server-side gate).
6. After inserting a passkey credential (the begin/finish or a direct seed of a credential row to simulate enrolment in the deterministic path) → `GET /admin/bootstrap/status` → `open:false`; re-`POST /admin/bootstrap/redeem` correct code → **403 `bootstrap_closed`** (V-B4 durable-close guard).

> Step 6's credential insert: prefer the real passkey FINISH; if a headless FINISH isn't feasible in the deterministic curl path, insert a `credentials(kind='passkey')` row via `psql` to exercise the count-gate close (the full ceremony is covered by Task 10 Playwright). Document this in a comment.

**Step — verify:** run `seed/seed.sh` then `test/run.sh` → `Results: N passed, 0 failed`. Capture transcript to `test/artifacts/`.

**Commit:** `test(scenario-101): deterministic curl smoke (bootstrap open/redeem/gate/close)`.

### Task 10: Playwright virtual-authenticator spec + spike

**Files:** Create `e2e/tests/scenario-101-auth-admin-bootstrap.spec.ts`; modify the scenario's Playwright project config to launch chromium with `--enable-blink-features=WebAuthenticationTesting`.

**Step 1 — spike (Assumption 4):** minimal local test: `CDPSession` → `WebAuthn.enable` → `addVirtualAuthenticator` (ctap2/internal, residentKey) against the running stack. If headless rejects it, fall back to asserting passkey `register/begin` returns a valid challenge + document the limitation in the spec + EXPLORATORY.md.

**Step 2 — spec:** virtual authenticator: (a) open `/admin` → bootstrap form visible (open); (b) submit `AUTH_BOOTSTRAP_CODE` → session (token stored in-memory/sessionStorage); (c) enrol passkey via register begin/finish (virtual authenticator auto-attests); (d) logout; (e) login via passkey begin/finish; (f) reload `/admin` → bootstrap form GONE (closed). 

**Step — verify:** `cd e2e && SCENARIO_URL=http://127.0.0.1:18101 npx playwright test scenario-101-auth-admin-bootstrap.spec.ts --reporter=list` → pass (or documented fallback).

**Commit:** `test(scenario-101): playwright virtual-authenticator passkey enrol+login spec`.

### Task 11: Register + playwright-cli exploratory QA + finalize (DoD)

**Files:** Modify `scenarios.json` (add `101-auth-admin-bootstrap` entry); Create `scenarios/101-auth-admin-bootstrap/test/EXPLORATORY.md`.

**Step 1:** Add the scenario to `scenarios.json` following the existing entry shape (id, status, components, test path).

**Step 2 — playwright-cli exploratory QA (DoD, per user):** with the stack up (`seed.sh`), use the `playwright-cli` skill (headless, isolated session) at `http://127.0.0.1:18101`: walk bootstrap form → redeem → enrol passkey → logout → passkey login → confirm bootstrap form gone. Capture screenshots at each step. Record observations + screenshot paths in `test/EXPLORATORY.md`. Then `docker compose down`.

**Step 3 — final verify:** `make test SCENARIO=101-auth-admin-bootstrap` (or `bash scenarios/101-auth-admin-bootstrap/test/run.sh`) → 0 failed; Playwright pass/documented-fallback; EXPLORATORY.md present with screenshots.

**Step 4:** Commit + PR + monitor + admin-merge on green.
```bash
git add scenarios/101-auth-admin-bootstrap/ scenarios.json e2e/tests/scenario-101-auth-admin-bootstrap.spec.ts
git commit -m "test(scenario-101): register + playwright-cli exploratory QA (EXPLORATORY.md)"
```
**Rollback:** revert PR; remove the `101-auth-admin-bootstrap` entry from `scenarios.json`; no other scenario touched.

---

## Post-merge follow-ups (file as issues, do not implement)

- gocodealone-multisite: migrate `cmd/multisite-host/admin_bootstrap.go` onto `step.auth_bootstrap_redeem` + `step.auth_jwt_issue` (retire the permanent-shared-secret + bespoke mint).
- workflow-plugin-auth Phase II: full IDP (`auth.idp`, JWKS, refresh, asymmetric/ES256) per ADR-0002.
- Close issue #23 with the shipped-evidence summary; close issue #21 after Task-1-of-the-#21-verification (separate track).
