# Auth Admin Contracts Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Add strict auth admin contracts to workflow-plugin-auth and prove them in workflow-scenarios without demo-only auth state.

**Architecture:** workflow-plugin-auth adds two strict proto step contracts: describe and validate auth admin config. The admin UI receives renderable control descriptors and submits config patches; the plugin validates and returns accepted patches while the host/scenario owns persistence.

**Tech Stack:** Go, protobuf, Workflow external plugin SDK, wfctl contract validation, workflow-scenarios Python/JS/Playwright/Docker.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 2
**Tasks:** 7
**Estimated Lines of Change:** ~900

**Out of scope:**
- Adding new auth providers beyond currently implemented runtime support.
- Persisting Workflow config inside workflow-plugin-auth.
- Replacing the admin plugin renderer architecture outside the scenario proof.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Auth plugin admin contracts | Task 1, Task 2, Task 3, Task 7 | feat/auth-admin-contracts |
| 2 | Scenario auth admin proof | Task 4, Task 5, Task 6 | pr-27-v2 |

**Status:** Locked 2026-05-27T06:23:26Z

### Task 1: Auth Admin Contract Tests

**Files:**
- Create: `internal/step_admin_config_test.go`
- Modify: `internal/plugin_contracts_test.go`

**Steps:**
1. Write failing tests for `newAuthAdminConfigDescribeStep`:
   - passkey controls show `webauthn_rp_id`/`webauthn_origin`.
   - password control maps to `password_auth_enabled`.
   - Google/Facebook OAuth groups expose provider labels and secret configured flags.
   - Instagram/X are either absent or `enabled=false` with `disabled_reason`.
2. Write failing tests for `newAuthAdminConfigValidateStep`:
   - rejects `environment=production` + `password_auth_enabled=true`.
   - rejects zero primary methods when `require_primary_method=true`.
   - accepts passkey config with RP ID + HTTPS origin.
   - redacts all configured secrets from output.
3. Add registry test requirements for:
   - `step.auth_admin_config_describe`
   - `step.auth_admin_config_validate`
4. Run: `GOWORK=off go test ./internal -run 'TestAuthAdmin|TestContractRegistry' -count=1`
5. Expected: FAIL with missing constructor/step/contract symbols.

**Verification:** failing tests prove contract and security expectations before implementation.

**Rollback:** remove test file and registry expectations.

### Task 2: Auth Admin Proto and Runtime Implementation

**Files:**
- Modify: `internal/contracts/auth.proto`
- Modify: `internal/contracts/auth.pb.go`
- Create: `internal/step_admin_config.go`
- Modify: `internal/plugin.go`

**Steps:**
1. Add protobuf messages:
   - `AuthAdminConfig`
   - `AuthAdminDescribeInput`
   - `AuthAdminControlOption`
   - `AuthAdminControl`
   - `AuthAdminControlGroup`
   - `AuthAdminDiagnostic`
   - `AuthAdminDescribeOutput`
   - `AuthAdminValidateConfig`
   - `AuthAdminValidateInput`
   - `AuthAdminValidateOutput`
2. Regenerate Go protobuf bindings:
   - `protoc --go_out=. --go_opt=paths=source_relative internal/contracts/auth.proto`
3. Implement shared helpers in `step_admin_config.go`:
   - merge config/runtime/current/input with existing `mergePolicyInputs`.
   - build groups for Primary methods, Second factors, OAuth providers, Delivery/Secrets.
   - classify `input_type` as `toggle`, `text`, `url`, `secret`, `select`.
   - return labels/descriptions/help text for each control.
   - redact secret values; expose only `configured`.
4. Implement describe step using `buildAuthMethodsPolicy`.
5. Implement validate step:
   - merge desired config patch.
   - reject production password enable.
   - reject zero primary method when required.
   - reject passkey enable without RP ID + HTTPS origin.
   - reject OAuth enable without routes + provider client ID/secret/redirect.
   - reject non-HTTPS OAuth URLs unless `allow_insecure_test_oauth_endpoints=true`.
6. Register legacy and typed step factories in `internal/plugin.go`.
7. Run: `gofmt -w internal/step_admin_config.go internal/plugin.go`
8. Run: `GOWORK=off go test ./internal -run 'TestAuthAdmin|TestContractRegistry' -count=1`
9. Expected: PASS.

**Verification:** focused Go tests pass and generated proto compiles.

**Rollback:** revert Task 2 files; Task 1 tests fail again until reverted.

### Task 3: Manifest, Docs, and Contract Validation

**Files:**
- Modify: `plugin.json`
- Modify: `plugin.contracts.json`
- Modify: `README.md`
- Modify: `SPEC.md`
- Modify: `CHANGELOG.md`

**Steps:**
1. Add both admin step types to `plugin.json`.
2. Add strict proto descriptors to `plugin.contracts.json`.
3. Bump manifest/download references to next patch version after latest tag (`v0.2.9` unless tags changed before release).
4. Document admin contract semantics:
   - plugin validates config patches.
   - host/admin persists accepted patches.
   - secrets are write-only/redacted.
5. Update SPEC with admin-contract constraints/invariants.
6. Update CHANGELOG with unreleased/new version entry.
7. Run:
   - `GOWORK=off go test ./...`
   - `wfctl plugin validate-contract --for-publish --tag v0.2.9 .`
   - `PLUGIN_MANIFEST_EXPECT_VERSION=0.2.9 GOWORK=off go test ./internal -run TestIntegration_PluginManifestAndStepTypes -count=1`
8. Expected:
   - Go tests report `ok`/`?`.
   - wfctl validation exits 0.
   - manifest integration test exits 0.
9. Commit Tasks 1-3.

**Verification:** plugin contract validates through wfctl and tests.

**Rollback:** revert manifest/docs/version commit; do not publish tag.

### Task 4: Scenario API Uses Contract-Shaped Auth Admin Surface

**Files:**
- Modify: `/Users/jon/workspace/workflow-scenarios/scenarios/99-*/...` or current admin scenario app files after locating the running admin demo.
- Modify/Create: matching scenario tests under `/Users/jon/workspace/workflow-scenarios/e2e` or scenario `test/`.

**Steps:**
1. Locate current admin/authz scenario implementation with `rg -n "authz|admin|roles|scopes" scenarios`.
2. Add `/api/admin/auth/config` or existing-route equivalent returning the same shape as `AuthAdminDescribeOutput`.
3. Add `/api/admin/auth/config/validate` or existing-route equivalent accepting desired config patch and returning `AuthAdminValidateOutput` shape.
4. Keep persistence scenario-local but explicit: scenario stores accepted config patch in its demo state; plugin contract remains source of shape/validation semantics.
5. Keep endpoint behind the existing admin login/session/scope guard.
6. Add tests:
   - anonymous request returns 401/redirect.
   - non-admin user returns 403.
   - admin can fetch descriptors.
   - unsafe password-in-production patch returns validation error.
   - valid passkey patch returns accepted config without secrets.
7. Run the scenario API test command discovered in the repo.
8. Expected: tests pass and unauthenticated admin access is blocked.

**Verification:** scenario API proves admin consumer boundary and auth guard.

**Rollback:** revert scenario API/test commit.

### Task 5: Scenario Admin UX for Auth and Authz Usability

**Files:**
- Modify: `/Users/jon/workspace/workflow-scenarios/<admin-ui-files-found-in-Task-4>`
- Modify/Create: Playwright specs under `/Users/jon/workspace/workflow-scenarios/e2e/tests/`

**Steps:**
1. Add an Authentication tab to the admin portal navigation.
2. Render auth groups/controls from contract-shaped API payload.
3. Use controls from payload:
   - toggles for booleans.
   - select/picker for known options.
   - secret inputs that never display existing values.
   - URL/text fields with labels and helper tooltip text.
4. Improve authz form labels/tooltips:
   - distinguish subject/user/role/resource/action/context.
   - keep scope fields picker-backed by declared scopes.
   - clarify admin vs frontend scope context.
5. Submit config patches through validation endpoint; show errors/warnings from diagnostics.
6. Add Playwright checks:
   - tabs group auth/authz forms.
   - auth controls render labels and tooltip/help text.
   - scope picker has known scopes and no free-text requirement.
   - auth validation error renders for production password attempt.
7. Run: scenario Playwright command discovered in repo.
8. Expected: Playwright passes and screenshots show no overlapping/ambiguous labels.

**Verification:** browser UI consumes descriptors and improves admin usability.

**Rollback:** revert scenario UI/test commit.

### Task 6: Runtime, Docker/Tailnet, and Exploratory QA

**Files:**
- Modify only scenario launch/config files if runtime validation exposes a required wiring defect.

**Steps:**
1. Rebuild/relaunch the scenario Docker or k8s app using the repo's existing scripts.
2. Preserve existing Tailscale sidecar/host serve path.
3. Verify local app:
   - `curl -i http://127.0.0.1:18080/admin` anonymous returns login/401, not admin data.
   - login as admin.
   - fetch auth/admin descriptors.
   - submit safe and unsafe auth config patches.
4. Verify tailnet reachability using the existing tailnet URL if available.
5. Run exploratory QA with `npx playwright`/Playwright CLI:
   - admin login.
   - Authentication tab.
   - Authz tab.
   - scopes picker.
   - role-scope assignment enforcement smoke.
6. Capture any UI/security defects, fix within Tasks 4/5 scope, and rerun checks.

**Verification:** running app is reachable locally and over tailnet; admin remains auth-gated; UX paths work in browser.

**Rollback:** stop scenario containers and revert scenario commits.

### Task 7: Release Auth Plugin

**Files:**
- No code files unless release verification finds a bug in Tasks 1-3.

**Steps:**
1. Re-run final auth plugin checks:
   - `GOWORK=off go test ./...`
   - `wfctl plugin validate-contract --for-publish --tag v0.2.9 .`
   - `git diff --check`
2. Confirm `plugin.json` version and download URLs match release tag.
3. Tag release:
   - `git tag v0.2.9`
   - `git push origin feat/auth-admin-contracts`
   - `git push origin v0.2.9`
4. Monitor release workflow with `gh run list --workflow release.yml --limit 5` and `gh run watch <run-id>`.
5. Expected: release workflow succeeds; if it fails, fix forward and publish next patch tag.

**Verification:** GitHub release workflow green for the new auth plugin tag.

**Rollback:** public tags are not deleted; fix forward with next patch tag or revert commit and publish rollback tag.

## Plan Adversarial Review
### Report
**Phase:** plan  
**Artifact:** `docs/plans/2026-05-27-auth-admin-contracts.md`  
**Status:** PASS

| sev | class | loc | issue | fix |
|---|---|---|---|---|
| Minor | Hidden dependency | Task 4 | Scenario cannot execute actual Go plugin step unless host wiring exists. | Keep scenario claim to contract-shaped consumer proof; plugin validation is proven in Go/wfctl. |
| Minor | Release risk | Task 7 | Tagging from feature branch may publish before PR merge. | User explicitly requested releases; gate on local validation and fix-forward on failure. |
| Minor | Task granularity | Task 2 | Proto + implementation in one task is larger than 2-5 minutes. | Kept together because generated bindings and implementation must compile atomically. |

### Bug-Class Scan
| class | result | note |
|---|---|---|
| Project-guidance conflicts | Clean | Plugin-first, strict contract, scenario proof preserved. |
| Assumptions under attack | Clean | Host persistence assumption isolated to accepted patch output. |
| Repo-precedent conflicts | Clean | Uses existing strict step factory/contract registry pattern. |
| YAGNI | Clean | No new auth providers or service framework added. |
| Missing failure modes | Clean | Unsafe auth changes, secret redaction, anonymous admin access included. |
| Security/privacy | Clean | Tests include auth gate, redaction, zero-primary, production password. |
| Infrastructure impact | Clean | Release tag impact and runtime Docker/tailnet validation included. |
| Multi-component validation | Clean | Plugin/wfctl boundary + scenario/UI boundary both tested. |
| Rollback wiring | Clean | Each runtime/release task includes rollback. |
| Verification-class mismatch | Clean | Plugin contract uses wfctl; UI uses Playwright; runtime uses launched app/curl. |
| Hidden serial dependencies | Clean | PR grouping separates plugin and scenario; scenario depends on plugin contract shape only. |
| User-intent drift | Clean | Addresses real auth plugin contracts and updated demo. |

## Alignment Report
**Status:** PASS

| Design Requirement | Plan Task(s) | Status |
|---|---|---|
| R1 real plugin admin config | Task 1, Task 2, Task 3 | Covered |
| R2 administrable auth modes | Task 1, Task 2, Task 5 | Covered |
| R3 toggles wired to plugin config | Task 1, Task 2, Task 4, Task 5 | Covered |
| R4 plugin-first scenario proof | Task 4, Task 5, Task 6 | Covered |
| R5 security standard | Task 1, Task 2, Task 4, Task 6 | Covered |
| R6 releases | Task 3, Task 7 | Covered |
| Strict proto contracts | Task 2, Task 3 | Covered |
| Multi-component validation | Task 3, Task 4, Task 6 | Covered |

| Plan Task | Design Requirement | Status |
|---|---|---|
| Task 1 | R1/R2/R5 | Justified |
| Task 2 | R1/R2/R3/R5 | Justified |
| Task 3 | R1/R6/strict proto | Justified |
| Task 4 | R4/R5 | Justified |
| Task 5 | R2/R3/R4 | Justified |
| Task 6 | R4/R5/multi-component validation | Justified |
| Task 7 | R6 | Justified |

**Drift Items:** none.
