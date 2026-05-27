# Auth Provider Architecture Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Build SDK-backed, plugin-first auth provider integrations and make auth/admin provider UI fully dynamic.

**Architecture:** `workflow-plugin-auth` defines strict shared provider descriptor contracts and consumes provider descriptors dynamically. Existing and new provider plugins expose descriptor steps plus provider-specific SDK-backed management/runtime steps. `workflow-scenarios` composes the app/admin stack to prove dynamic admin rendering, auth/authz gating, provider selection, and runtime enforcement.

**Tech Stack:** Go, Workflow plugin SDK strict proto contracts, wfctl, official Okta/Auth0/Microsoft/Ory/Scalekit SDKs or documented official REST API where no Go SDK exists, Docker/Kubernetes scenario deployment, Playwright CLI.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 9
**Tasks:** 13
**Estimated Lines of Change:** ~9000

**Out of scope:**
- Production deployment to external clouds or real customer tenants.
- Storing live provider credentials in git, scenarios, or release workflows.
- Replacing `workflow-plugin-authz` authorization engines.
- Replacing `workflow-plugin-admin` shell rendering beyond consuming dynamic contributions/descriptors.
- Claiming Ory Polis has an official Go SDK unless one is verified during implementation.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Auth provider descriptor contracts | Task 1, Task 2 | feat/auth-provider-descriptors |
| 2 | Generic SSO descriptor integration | Task 3 | feat/sso-provider-descriptors |
| 3 | Okta provider descriptor hardening | Task 4 | feat/okta-provider-descriptors |
| 4 | Auth0 provider plugin | Task 5 | feat/auth0-provider-plugin |
| 5 | Entra provider plugin | Task 6 | feat/entra-provider-plugin |
| 6 | Ory Kratos and Hydra provider plugins | Task 7, Task 8 | feat/ory-auth-plugins |
| 7 | Enterprise SSO/SCIM provider plugins | Task 9, Task 10 | feat/enterprise-sso-scim-providers |
| 8 | Scenario admin/runtime proof | Task 11, Task 12 | feat/provider-admin-scenario |
| 9 | Release cascade and retrospective | Task 13 | chore/auth-provider-release-cascade |

**Status:** Locked 2026-05-27T14:17:48Z

### Task 1: Core Provider Descriptor Contract Tests

**Files:**
- Modify: `workflow-plugin-auth/internal/contracts/auth.proto`
- Modify: `workflow-plugin-auth/internal/plugin.go`
- Modify: `workflow-plugin-auth/internal/plugin_contracts_test.go`
- Create: `workflow-plugin-auth/internal/step_provider_catalog_test.go`
- Modify: `workflow-plugin-auth/plugin.contracts.json`
- Modify: `workflow-plugin-auth/plugin.json`

**Steps:**
1. Write failing tests for `AuthProviderDescriptor`, `AuthProviderCapability`, and `AuthProviderConfigField` strict proto field presence.
2. Write failing tests for `step.auth_provider_catalog` merging provider descriptors from config/current input.
3. Assert catalog merge de-duplicates by provider ID and rejects duplicate capability keys with incompatible metadata.
4. Assert secret fields are only represented by key/configured state and never echo values.
5. Assert runtime `ContractRegistry()` and `plugin.contracts.json` include `step.auth_provider_catalog`.
6. Run: `GOWORK=off go test ./internal -run 'TestAuthProvider|TestContractRegistry|TestProtoFields' -count=1`.
7. Expected: new tests fail before implementation and pass after Task 2.

**Verification:** strict proto and contract registry tests prove descriptor contract shape before runtime use.

**Rollback:** revert PR 1; existing auth admin fallback remains available.

### Task 2: Dynamic Auth Admin Provider Rendering

**Files:**
- Modify: `workflow-plugin-auth/internal/contracts/auth.proto`
- Modify: `workflow-plugin-auth/internal/contracts/auth.pb.go`
- Modify: `workflow-plugin-auth/internal/step_admin_config.go`
- Modify: `workflow-plugin-auth/internal/step_methods_policy.go`
- Modify: `workflow-plugin-auth/internal/step_oauth.go`
- Modify: `workflow-plugin-auth/internal/typed.go`
- Modify: `workflow-plugin-auth/internal/plugin.go`
- Modify: `workflow-plugin-auth/internal/step_admin_config_test.go`
- Modify: `workflow-plugin-auth/README.md`
- Modify: `workflow-plugin-auth/SPEC.md`

**Steps:**
1. Add `AuthProviderDescriptor`, `AuthProviderCapability`, `AuthProviderConfigField`, `AuthProviderCatalogInput`, and `AuthProviderCatalogOutput` messages.
2. Generate protobuf Go code with `protoc --go_out=. --go_opt=paths=source_relative internal/contracts/auth.proto`.
3. Implement `newAuthProviderCatalogStep` and typed step registration.
4. Extend `AuthAdminConfig`/`AuthAdminDescribeInput` with repeated provider descriptors.
5. Refactor `buildOAuthAdminControls` to read descriptors and capability config fields; keep Google/Facebook compatibility fallback only when no provider descriptors are supplied.
6. Refactor OAuth policy provider support to derive advertised providers from descriptors when supplied.
7. Add built-in descriptor generation for local auth methods: passkey, password dev-only, TOTP, magic link, email code, SMS challenge.
8. Update tests so Auth0/Entra/Okta controls render from supplied descriptors without auth-core vendor constants.
9. Add tests that unsupported descriptors show disabled reason and cannot validate as enabled.
10. Run `gofmt`.
11. Run `GOWORK=off go test ./...`.
12. Run `GOWORK=off go vet ./...`.
13. Run `wfctl plugin validate-contract .`.
14. Open PR #1; after merge, release next patch tag for `workflow-plugin-auth`.

**Verification:** plugin tests, vet, contract validation, and release CI prove auth core is dynamic and backward compatible.

**Rollback:** revert PR 1 or publish next patch restoring prior admin controls.

### Task 3: Generic SSO Descriptor Integration

**Files:**
- Modify/Create in `workflow-plugin-sso`: `internal/contracts/sso.proto`
- Modify/Create: `workflow-plugin-sso/internal/step_provider_describe.go`
- Modify: `workflow-plugin-sso/internal/plugin.go`
- Modify: `workflow-plugin-sso/internal/oidc.go`
- Modify: `workflow-plugin-sso/internal/entra_provider.go`
- Modify/Create: `workflow-plugin-sso/internal/auth0_provider.go`
- Modify: `workflow-plugin-sso/plugin.contracts.json`
- Modify: `workflow-plugin-sso/README.md`

**Steps:**
1. Add `step.sso_auth_provider_describe` returning auth-compatible provider descriptors for generic OIDC, Okta issuer helper, Entra issuer helper, and Auth0 issuer helper.
2. Keep `workflow-plugin-sso` as generic OIDC runtime; do not duplicate vendor management APIs here.
3. Add Auth0 issuer/domain helper and tests.
4. Add tests that provider descriptors include OIDC scopes, issuer URL, callback config fields, claim mappings, PKCE/state requirements, and admin/app scopes.
5. Add tests that token validation rejects unknown issuer/provider and preserves existing behavior.
6. Run `GOWORK=off go test ./...`.
7. Run `GOWORK=off go vet ./...`.
8. Run `wfctl plugin validate-contract .`.
9. Open PR #2; after merge, release next patch tag for `workflow-plugin-sso`.

**Verification:** generic OIDC descriptor step plus existing token-validation tests prove SSO is not redundant and remains runtime-focused.

**Rollback:** revert PR 2; generic OIDC module/steps remain unchanged.

### Task 4: Okta Provider Descriptor Hardening

**Files:**
- Modify in `workflow-plugin-okta`: `internal/contracts/*.proto` or create strict proto contracts if absent.
- Modify/Create: `workflow-plugin-okta/internal/step_provider_describe.go`
- Modify: `workflow-plugin-okta/internal/module.go`
- Modify: `workflow-plugin-okta/okta/provider.go`
- Modify: `workflow-plugin-okta/plugin.contracts.json`
- Modify: `workflow-plugin-okta/README.md`

**Steps:**
1. Add `step.okta_auth_provider_describe` with categories `identity_management`, `oauth2_oidc`, `enterprise_sso`, and `directory_sync` only for already implemented Okta APIs.
2. Ensure descriptors use official Okta Go SDK v6-backed module config and least-privilege default scopes.
3. Add tests that API-token and private-key modes are mutually exclusive and descriptor scopes match auth mode.
4. Add tests for user/group/app/auth-server capability descriptors pointing at existing Okta steps.
5. Remove misleading `Experimental` wording only if integration tests prove the covered capabilities with httptest/SDK mock transport.
6. Run `GOWORK=off go test ./...`.
7. Run `GOWORK=off go vet ./...`.
8. Run `wfctl plugin validate-contract .`.
9. Open PR #3; after merge, release next patch tag for `workflow-plugin-okta`.

**Verification:** descriptors map only to SDK-backed Okta capabilities already implemented and tested.

**Rollback:** revert PR 3; Okta management steps remain usable without descriptors.

### Task 5: Auth0 Provider Plugin

**Files:**
- Create repo: `workflow-plugin-auth0`
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Create: `cmd/workflow-plugin-auth0/main.go`
- Create: `internal/contracts/auth0.proto`
- Create: `internal/module.go`
- Create: `internal/plugin.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_users.go`
- Create: `internal/step_roles.go`
- Create: `internal/step_connections.go`
- Create: `auth0/provider.go`
- Create: `plugin.json`, `plugin.contracts.json`, `README.md`, `Makefile`

**Steps:**
1. Scaffold a standard Workflow plugin repo with strict proto contract tests.
2. Use official `github.com/auth0/go-auth0/v2` Authentication and Management clients.
3. Implement module `auth0.provider` with domain plus token or client-credentials config.
4. Implement `step.auth0_auth_provider_describe`.
5. Implement SDK-backed management steps: user list/get/create/update/delete, role list/get/assign/remove, connection list/get.
6. Implement Authentication API descriptor for Auth Code + PKCE; leave app callback persistence to consuming app.
7. Add httptest-backed SDK tests for each advertised step and error mapping.
8. Add contract registry/manifest tests.
9. Add README security guidance: no password grant by default, PKCE/state required, management token least privilege.
10. Run `GOWORK=off go test ./...`.
11. Run `GOWORK=off go vet ./...`.
12. Run `wfctl plugin validate-contract .`.
13. Create GitHub repo if absent, open PR #4, merge after green CI, release `v0.1.0`.

**Verification:** official SDK-backed local tests and contract validation prove real Auth0 provider functionality without live credentials.

**Rollback:** do not install the plugin in scenarios/registry; publish corrective patch if tag is bad.

### Task 6: Entra Provider Plugin

**Files:**
- Create repo: `workflow-plugin-entra`
- Create standard plugin files mirroring Task 5.
- Create: `entra/provider.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_users.go`
- Create: `internal/step_groups.go`
- Create: `internal/step_apps.go`
- Create: `internal/step_auth_methods_policy.go`

**Steps:**
1. Scaffold `workflow-plugin-entra` with strict proto contracts.
2. Use official Microsoft Graph Go SDK and Azure/Kiota auth libraries.
3. Implement module `entra.provider` with tenant ID, client ID, and secret/cert credential config.
4. Implement provider descriptors for `identity_management`, `oauth2_oidc`, `enterprise_sso`, and `directory_sync`.
5. Implement users list/get/create/update/delete where Graph SDK supports testable methods.
6. Implement groups list/get/member add/remove.
7. Implement app registration list/get/create for OIDC app management.
8. Implement auth-method policy describe/update only where Graph SDK permissions are clear; otherwise mark unavailable with reason.
9. Add httptest/request-adapter tests for advertised SDK calls.
10. Add README least-privilege Graph permission guidance.
11. Run `GOWORK=off go test ./...`.
12. Run `GOWORK=off go vet ./...`.
13. Run `wfctl plugin validate-contract .`.
14. Create GitHub repo if absent, open PR #5, merge after green CI, release `v0.1.0`.

**Verification:** Graph SDK-backed tests prove Entra user/group/app provider operations and descriptors.

**Rollback:** do not install plugin in scenarios/registry; publish corrective patch if tag is bad.

### Task 7: Ory Kratos Provider Plugin

**Files:**
- Create repo: `workflow-plugin-ory-kratos`
- Create standard plugin files.
- Create: `orykratos/provider.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_identities.go`
- Create: `internal/step_flows.go`

**Steps:**
1. Verify current official Kratos Go client package and version before implementation.
2. Scaffold strict plugin contracts.
3. Implement module `ory.kratos` using the official Kratos client for self-hosted Kratos or Ory Network SDK only when configured.
4. Implement provider descriptors for `identity_management` and `authentication_method`.
5. Implement identity list/get/create/update/delete steps.
6. Implement registration/login/recovery/verification flow start or inspect steps only where SDK/API semantics are clear and testable.
7. Mark passkey/passwordless/2FA support as available only if descriptor is backed by a real flow/config API call.
8. Add httptest tests for each advertised endpoint.
9. Run `GOWORK=off go test ./...`.
10. Run `GOWORK=off go vet ./...`.
11. Run `wfctl plugin validate-contract .`.
12. Create repo/PR #6 part A, merge after green CI.

**Verification:** Kratos SDK-backed identity/flow tests and descriptors prove real identity-management integration.

**Rollback:** leave plugin uninstalled from scenarios/registry or publish patch.

### Task 8: Ory Hydra Provider Plugin

**Files:**
- Create repo: `workflow-plugin-ory-hydra`
- Create standard plugin files.
- Create: `oryhydra/provider.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_clients.go`
- Create: `internal/step_jwks.go`

**Steps:**
1. Verify current official Hydra Go client package and version before implementation.
2. Implement module `ory.hydra` with admin URL and credential config.
3. Implement provider descriptors for `oauth2_oidc`.
4. Implement OAuth2 client list/get/create/update/delete steps.
5. Implement JWKS metadata/list steps if SDK supports them.
6. Do not implement consent/login UI in this plugin unless it can be backed by real Hydra APIs and scenario wiring.
7. Add httptest tests for each advertised Hydra admin API call.
8. Run `GOWORK=off go test ./...`.
9. Run `GOWORK=off go vet ./...`.
10. Run `wfctl plugin validate-contract .`.
11. Finish PR #6 with Kratos/Hydra or split if review size requires explicit amendment.
12. Release `workflow-plugin-ory-kratos v0.1.0` and `workflow-plugin-ory-hydra v0.1.0`.

**Verification:** Hydra SDK-backed tests prove OIDC provider management capability.

**Rollback:** leave plugin uninstalled from scenarios/registry or publish patch.

### Task 9: Ory Polis Provider Plugin

**Files:**
- Create repo: `workflow-plugin-ory-polis`
- Create standard plugin files.
- Create: `polis/provider.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_sso_connections.go`
- Create: `internal/step_directory_sync.go`

**Steps:**
1. Verify whether a stable official Ory Polis Go SDK exists.
2. If official Go SDK exists, use it. If not, implement a small typed HTTP client over the official Polis/Jackson API and record the absence of a Go SDK in README and descriptor metadata.
3. Implement module `ory.polis` with API base URL and token config.
4. Implement provider descriptors for `enterprise_sso` and `directory_sync`.
5. Implement SSO connection list/get/create/update/delete steps.
6. Implement directory sync connection list/get and SCIM event/status steps where API supports them.
7. Add httptest tests for each advertised endpoint; do not advertise unimplemented SAML or SCIM operations.
8. Run `GOWORK=off go test ./...`.
9. Run `GOWORK=off go vet ./...`.
10. Run `wfctl plugin validate-contract .`.
11. Create repo/PR #7 part A, merge after green CI.

**Verification:** Polis API-backed tests prove real enterprise SSO/SCIM management without claiming a nonexistent Go SDK.

**Rollback:** leave plugin uninstalled from scenarios/registry or publish patch.

### Task 10: Scalekit Enterprise SSO/SCIM Provider Plugin

**Files:**
- Create repo: `workflow-plugin-scalekit`
- Create standard plugin files.
- Create: `scalekit/provider.go`
- Create: `internal/step_provider_describe.go`
- Create: `internal/step_connections.go`
- Create: `internal/step_directory.go`

**Steps:**
1. Verify current official Scalekit Go SDK package and version.
2. Implement module `scalekit.provider` using the official SDK.
3. Implement provider descriptors for `enterprise_sso` and `directory_sync`.
4. Implement SSO connection list/get/create/update/delete steps and SCIM/directory steps supported by SDK.
5. Add httptest/SDK mock tests for each advertised call.
6. Run `GOWORK=off go test ./...`.
7. Run `GOWORK=off go vet ./...`.
8. Run `wfctl plugin validate-contract .`.
9. Finish PR #7; release `workflow-plugin-ory-polis v0.1.0` and `workflow-plugin-scalekit v0.1.0`.

**Verification:** non-Ory enterprise SSO/SCIM provider proves Ory is not the only implementation path.

**Rollback:** leave plugin uninstalled from scenarios/registry or publish patch.

### Task 11: Scenario Dynamic Admin Provider UX

**Files:**
- Modify in `workflow-scenarios`: current admin/authz scenario API files.
- Modify: scenario admin UI files.
- Modify: scenario workflow YAML and plugin version pins.
- Modify/Create: scenario tests.

**Steps:**
1. Update scenario plugin pins to released auth/admin/authz/sso/provider plugin versions.
2. Compose provider descriptor steps for local auth, generic OIDC, Okta, Auth0, Entra, Kratos, Hydra, Polis, and Scalekit using local/mock configs.
3. Expose admin endpoint returning merged provider catalog and auth admin describe output.
4. Update admin UI provider settings tabs to render descriptors dynamically with clear labels/tooltips.
5. Ensure provider, capability, scope, role, and config options are lookup-backed where descriptor options exist.
6. Hide or disable controls when current admin user lacks required admin scope.
7. Add scenario tests:
   - anonymous admin blocked.
   - app user cannot see admin provider controls.
   - provider-admin can view descriptors but cannot save secrets without write scope.
   - auth-admin can save accepted non-secret config.
   - provider choices come from descriptors, not hard-coded UI arrays.
8. Run scenario test script.
9. Run `wfctl validate` or repo-equivalent Workflow validation.

**Verification:** scenario API/UI proves dynamic admin UX, auth gate, authz gate, and lookup-backed controls.

**Rollback:** revert scenario PR; plugin releases remain independently usable.

### Task 12: Scenario Runtime, Docker/Kubernetes, Tailscale QA

**Files:**
- Modify in `workflow-scenarios`: Dockerfile/compose/Kubernetes manifests for admin provider scenario.
- Modify: tailscale sidecar manifests using existing local cluster secret names.
- Create/modify: Playwright CLI QA scripts or documented commands.

**Steps:**
1. Build and launch the scenario locally with Docker or the local Kubernetes cluster.
2. Include tailscale sidecar using existing cluster secret wiring; do not create or print secrets.
3. Rotate provider configuration across generic OIDC, Auth0, Entra, Okta, Kratos/Hydra, and enterprise SSO descriptors using local mock servers where live credentials are absent.
4. Verify runtime enforcement:
   - login/token validation succeeds for configured provider.
   - invalid issuer/audience/token fails closed.
   - provider-specific admin action requires provider write scope.
   - role/scope assignment still enforced through authz plugin.
5. Run Playwright CLI exploratory QA:
   - desktop and mobile admin views.
   - provider tabs and tooltips.
   - scope/role pickers.
   - save/reject diagnostics.
   - forbidden user flows.
6. Fix defects found by QA in plugin repos first when root cause is contract/runtime, scenario second only for composition bugs.
7. Provide local and tailnet reachable URLs when running.

**Verification:** launched app + admin portal with tailscale sidecar; Playwright screenshots and functional tests prove realistic operation.

**Rollback:** stop local deployment and revert scenario PR.

### Task 13: Release Cascade and Completion

**Files:**
- Modify: `plugin.json` versions in each changed plugin repo.
- Modify: release notes/CHANGELOG where repo has one.
- Modify: scenario plugin version pins.
- Create: retrospective doc if repo convention exists.
- Append: `/Users/jon/workspace/.autodev/state/phase-progress.jsonl`.

**Steps:**
1. For each changed plugin repo, run:
   - `GOWORK=off go test ./...`
   - `GOWORK=off go vet ./...`
   - `wfctl plugin validate-contract --for-publish --tag vX.Y.Z .`
   - `git diff --check`
2. Create/merge PRs according to the manifest. Use `gh --version` before and after each `gh pr create`; add Copilot reviewer but do not wait on it.
3. After each merge, tag and push the next release.
4. Watch release CI for every tag and main CI for every merge.
5. Update `workflow-scenarios` pins only to released versions.
6. Re-run full scenario runtime and Playwright QA on released pins.
7. Run adversarial security review against final diffs and scenario behavior.
8. Record phase progress and, if all scope is complete, run `scope-lock-complete` with verification evidence.

**Verification:** all plugin releases are published, main/release CI is green, scenario runs against released artifacts, and admin portal is ready for user retest.

**Rollback:** publish patch releases from last known-good commits; scenario pins can revert to previous released versions.

## Adversarial Plan Review

### Report
**Phase:** plan  
**Artifact:** `docs/plans/2026-05-27-auth-provider-architecture.md`  
**Status:** PASS

| sev | class | loc | issue | fix |
|---|---|---|---|---|
| Minor | Over-decomposition | Scope Manifest | Nine PRs is heavy. | Accepted because user requested multiple real providers and releases; each PR is independently revertible. |
| Minor | Infrastructure | Tasks 5-10 | New repo creation has GitHub side effects. | Only create repos if absent; no production deploy; release each after tests. |
| Minor | Assumption | Task 9 | Polis Go SDK may not exist. | Plan requires verification and avoids claiming SDK support when absent. |

### Bug-Class Scan
| class | result | note |
|---|---|---|
| Project-guidance conflicts | Clean | Plugin boundaries follow workspace guidance. |
| Assumptions under attack | Clean | Provider SDK/API availability and no live credentials are explicit. |
| Repo-precedent conflicts | Clean | Existing strict proto/contract validation pattern is used. |
| YAGNI | Clean | Scope maps to user-requested providers/categories; no production deploy. |
| Missing failure modes | Clean | Invalid tokens, missing scopes, SDK drift, secret leakage, and provider mismatch covered. |
| Security/privacy | Clean | Least privilege, redaction, authz gates, and callback abuse cases included. |
| Infrastructure impact | Clean | New repos/releases/local deployment impacts listed. |
| Multi-component validation | Clean | Plugin-host-admin-scenario-runtime browser proof included. |
| Rollback | Clean | Each task has rollback notes. |
| Simpler alternative | Clean | Single auth monolith rejected in design due hard-coding risk. |
| User-intent drift | Clean | Directly addresses real providers, dynamic admin, authz-gated scenario, and releases. |
| Verification-class mismatch | Clean | Plugin, API, UI, runtime, and release checks match change classes. |
| Hidden serial dependencies | Clean | PR groups serialize shared contracts before provider/scenario consumers. |

## Alignment Report

**Status:** PASS

**Coverage:**
| Design Requirement | Plan Task(s) | Status |
|---|---|---|
| R1 go vet fix remains first | Task 13 evidence references completed release; no code task reopens it | Covered |
| R2 remove hard-coded admin/provider UI | Task 1, Task 2, Task 11 | Covered |
| R3 actual providers Okta/Auth0/Entra/Ory | Task 3, Task 4, Task 5, Task 6, Task 7, Task 8, Task 9 | Covered |
| R4 distinguish categories | Task 1, Task 2, provider descriptor tasks | Covered |
| R5 non-Ory implementations | Task 3, Task 4, Task 5, Task 6, Task 10 | Covered |
| R6 lookup-backed UI | Task 1, Task 2, Task 11 | Covered |
| R7 plugin-first with scenario proof | Task 1-12 | Covered |
| R8 releases | Task 13 | Covered |

**Scope Check:**
| Plan Task | Design Requirement | Status |
|---|---|---|
| Task 1 | Shared descriptor contracts | Justified |
| Task 2 | Dynamic auth admin provider rendering | Justified |
| Task 3 | Generic OIDC non-redundant SSO | Justified |
| Task 4 | Okta real provider | Justified |
| Task 5 | Auth0 real provider | Justified |
| Task 6 | Entra real provider | Justified |
| Task 7 | Ory Kratos identity provider | Justified |
| Task 8 | Ory Hydra OIDC provider | Justified |
| Task 9 | Ory Polis enterprise SSO/SCIM | Justified |
| Task 10 | Non-Ory enterprise SSO/SCIM | Justified |
| Task 11 | Dynamic admin UX scenario | Justified |
| Task 12 | Runtime/tailscale QA | Justified |
| Task 13 | Release cascade | Justified |

**Drift Items:** none.
