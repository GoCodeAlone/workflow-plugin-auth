# Auth Policy Gate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add reusable `step.auth_policy_gate` to `workflow-plugin-auth` so Workflow apps do not need BMW-local auth policy hardening.

**Architecture:** Implement the gate beside the existing auth method policy code. It reads a named previous policy step from the step result map, applies signing-secret and OAuth-provider safety filters, and emits the same policy-shaped output used by current BMW YAML.

**Tech Stack:** Go, Workflow plugin SDK, `go test`, plugin manifest JSON, Markdown docs.

---

### Task 1: Add Policy Gate Tests

**Files:**
- Modify: `internal/step_methods_policy_test.go`

**Step 1: Write failing tests**

Add `TestAuthPolicyGate` table cases:
- email code enabled without signing secret becomes disabled and count decrements.
- email code remains enabled with `signing_secret`.
- templated signing secret is treated as missing.
- unsupported OAuth providers are filtered to Google by default.
- missing policy step output returns disabled booleans, empty providers, and zero count.

**Step 2: Run tests to verify failure**

Run: `GOWORK=off go test ./internal -run TestAuthPolicyGate -count=1`

Expected: FAIL because `newAuthPolicyGateStep` does not exist.

**Step 3: Commit is deferred**

Do not commit until implementation and registration are included.

### Task 2: Implement `step.auth_policy_gate`

**Files:**
- Modify: `internal/step_methods_policy.go`

**Step 1: Implement minimal step**

Add `authPolicyGateStep` with constructor `newAuthPolicyGateStep(name string, config map[string]any)`.

Behavior:
- Read policy from `steps[policy_step]`; default `policy_step` is `policy`.
- Copy booleans: `passkey_enabled`, `email_code_enabled`, `sms_code_enabled`, `password_enabled`, `password_auth_enabled`, `totp_enabled`.
- Convert `oauth_providers` through existing `policyStringSlice`.
- Read signing secret from config, current input, runtime config, or environment-compatible source only if non-empty and not templated.
- Default supported OAuth providers to `[]string{"google"}`.
- Recompute `primary_method_count` from the output booleans and filtered providers.

**Step 2: Run tests to verify pass**

Run: `GOWORK=off go test ./internal -run TestAuthPolicyGate -count=1`

Expected: PASS.

### Task 3: Register and Advertise Step

**Files:**
- Modify: `internal/plugin.go`
- Modify: `plugin.json`
- Modify: `README.md`

**Step 1: Add registration**

Add `step.auth_policy_gate` to `allStepTypes` and `CreateStep`.

**Step 2: Add manifest/docs entries**

Add the step to `plugin.json` `stepTypes` and README Step Types. Document that it filters policy output and keeps app-specific storage outside the plugin.

**Step 3: Run integration verification**

Run: `GOWORK=off go test ./internal -run TestIntegration_PluginManifestAndStepTypes -count=1`

Expected: PASS and `CreateStep("step.auth_policy_gate")` succeeds through the loop.

### Task 4: Full Verification and Commit

**Files:**
- Modify: all files from prior tasks

**Step 1: Run full tests**

Run: `GOWORK=off go test ./...`

Expected: PASS for all packages.

**Step 2: Check formatting and whitespace**

Run: `gofmt -w internal/step_methods_policy.go internal/step_methods_policy_test.go && git diff --check`

Expected: no output from `git diff --check`.

**Step 3: Commit**

Run:

```bash
git add internal/step_methods_policy.go internal/step_methods_policy_test.go internal/plugin.go plugin.json README.md docs/plans/2026-04-26-auth-policy-gate-design.md docs/plans/2026-04-26-auth-policy-gate.md
git commit -m "feat: add reusable auth policy gate"
```

Expected: commit created on `feat/auth-policy-gate`.
