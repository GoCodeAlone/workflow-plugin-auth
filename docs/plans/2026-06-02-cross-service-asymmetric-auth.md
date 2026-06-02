# Cross-Service Asymmetric Auth (auth#41) — Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans.

**Goal:** Make Workflow fully support cross-service asymmetric (ES256) JWT auth via reuse: add a `jwksUri`-only verify mode to the existing `workflow-plugin-sso` `sso.oidc` provider, demonstrate genuine cross-process verification in a workflow-scenarios stack, document the use-case→combination matrix in workflow-plugin-auth, and close #41. No bespoke IDP.

**Architecture:** App A = `auth.m2m` ES256 issuer (publishes `/oauth/jwks`). App B = `sso.oidc` (new `jwksUri` mode, `oidc.NewRemoteKeySet`+`NewVerifier`) + `step.sso_validate_token` — verifies App A's token from App A's PUBLIC JWKS; no shared secret, no OIDC discovery, no mock-OIDC.

**Tech Stack:** Go 1.26; `github.com/coreos/go-oidc/v3 v3.12.0` (`NewRemoteKeySet`/`NewVerifier`); engine `auth.m2m` (ES256); docker-compose (2 engine processes); Playwright + playwright-cli.

**Base branch:** main (all three repos).

**Design:** `docs/plans/2026-06-02-cross-service-asymmetric-auth-design.md` (rev 2, adversarial PASS). ADR-0002, ADR-0003.

---

## Scope Manifest

**PR Count:** 3
**Tasks:** 9
**Estimated Lines of Change:** ~500 (informational)

**Out of scope:**
- Bespoke IDP (`auth.idp`, `step.auth_jwks_serve`, asymmetric `step.auth_jwt_issue`) — engine `auth.m2m` + `sso` cover it.
- M2M refresh tokens (client_credentials has none; re-issue) + `auth.m2m` multi-key verify.
- gocodealone-multisite adoption (#54). Fixing scenario-84's invalid `sso.oidc` config (separate hygiene).

**PR Grouping:**

| PR # | Title | Tasks | Branch / Repo |
|------|-------|-------|--------|
| 1 | feat: sso.oidc jwksUri verify mode | Task 1, Task 2, Task 3 | feat/sso-jwks-uri-verify (workflow-plugin-sso) |
| 2 | test: scenario 102 cross-service asymmetric auth | Task 4, Task 5, Task 6 | feat/scenario-102-cross-service-asymmetric (workflow-scenarios) |
| 3 | docs: auth use-case matrix + close #41 | Task 7, Task 8, Task 9 | feat/auth-41-usecase-matrix (workflow-plugin-auth) |

**Status:** Draft

---

## PR 1 — workflow-plugin-sso: `sso.oidc` jwksUri verify mode

Repo `/Users/jon/workspace/workflow-plugin-sso`, branch off origin/main. `GOWORK=off`.

### Task 1: `jwksUri` verify mode (TDD)

**Files:** Modify `internal/oidc.go` (`ProviderConfig` + `InitProvider`), `internal/module_oidc.go` (config parse); Test `internal/oidc_jwksuri_test.go`.

**Step 1 — failing test** (`internal/oidc_jwksuri_test.go`): use the existing `mockOIDCServer` (serves `/keys` JWKS + signs ES256/RS256 tokens). Build a provider via `InitProvider(ctx, ProviderConfig{Name:"app-a", Issuer: mock.URL, JWKSURI: mock.URL+"/keys", ClientID:"app-b"})` (note: NO discovery). Assert: `provider.Verifier.Verify(ctx, validToken)` succeeds for a token with `iss=mock.URL`, `aud=app-b`; fails for a token signed by a DIFFERENT key; fails for `aud!=app-b`; fails for `iss!=mock.URL`. (Mirror `oidc_test.go`'s mockOIDCServer token-minting helpers.)

**Step 2:** Run `GOWORK=off go test ./internal/ -run JWKSURI -v` → FAIL (JWKSURI field undefined).

**Step 3 — implementation:**
- `internal/oidc.go` `ProviderConfig`: add `JWKSURI string` field.
- `InitProvider`: branch at the top — when `cfg.JWKSURI != ""`:
  ```go
  keySet := oidc.NewRemoteKeySet(ctx, cfg.JWKSURI)
  verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
      ClientID:          cfg.ClientID,
      SkipClientIDCheck: cfg.ClientID == "",
  })
  // verify-only: no discovery, no OAuthCfg.Endpoint (refresh/exchange require discovery path)
  return &OIDCProvider{ProviderName: cfg.Name, Issuer: issuer, Verifier: verifier, OAuthCfg: &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: scopesOrDefault(cfg.Scopes)}, ClaimPaths: claimMapOrDefault(cfg.ClaimMapping)}, nil
  ```
  Keep the existing `oidc.NewProvider(ctx, issuer)` discovery path for the `else` (JWKSURI=="") case unchanged.
- `internal/module_oidc.go` provider parse: add `JWKSURI: getString(raw, "jwksUri")` to the `ProviderConfig` built from `raw`.

**Step 4:** Run `GOWORK=off go test ./internal/ -run JWKSURI -v` → PASS.

**Step 5:** Commit `feat(sso): jwksUri-only verify mode for sso.oidc (NewRemoteKeySet, no discovery)`.

### Task 2: Docs + manifest + full verification

**Files:** `README.md` (document `jwksUri` provider config: verify-only, cross-service/JWKS issuers without discovery), `plugin.json` (no new step/module type → no capabilities change; leave version discipline placeholder).

**Step — verify (Go-repo class):**
```
GOWORK=off go test -race ./... 2>&1 | tail -10   # green
GOWORK=off go build ./...                          # exit 0
GOWORK=off golangci-lint run --new-from-rev=origin/main ./...  # 0 issues
```
**Step:** Commit `docs(sso): document sso.oidc jwksUri verify mode`.

### Task 3: PR 1, monitor, merge, tag v0.1.7

**Rollback:** revert PR; don't advance tag; discovery path untouched.
- Pre-tag: `git ls-remote --tags origin | grep -c 'v0.1.7$'` → 0 (latest is v0.1.6).
- PR → CI green + Copilot clear → admin-merge → `git tag v0.1.7 && git push origin v0.1.7`.
- Registry manifest: only if the sso manifest tracks version/downloads — bump version→0.1.7 + downloads (no capabilities change). If notify-sync handles it, skip. Verify `gh release view v0.1.7`.

---

## PR 2 — workflow-scenarios: scenario 102 cross-service asymmetric auth

Repo `/Users/jon/workspace/workflow-scenarios`, branch off origin/main. **Depends on PR 1 merged** (builds sso from main). Scenario id **102** (verify against origin/main `scenarios.json`; 101 is taken). Templates: scenario 101 (image-bake seed, self-isolating tests, docker-compose) + 92 (multi-service).

### Task 4: Scenario scaffold — App A (issuer) + App B (verifier)

**Files (under `scenarios/102-cross-service-asymmetric-auth/`):** `scenario.yaml`, `README.md`, `config/app-a.yaml`, `config/app-b.yaml`, `docker-compose.yml`, `seed/seed.sh`.

- **`config/app-a.yaml` (issuer):** `http.server` + `router`; `auth.m2m` module `appissuer` with `algorithm: ES256` + a generated/configured EC private key + `issuer: http://app-a:8080` + a registered M2M client (`client_id`/`client_secret`) carrying **`claims: {aud: app-b}`** (cycle-2 N1 — confirm the auth.m2m `clients` config shape in `workflow/plugins/auth/plugin.go`; `issueToken` passes `client.Claims`). Mount the `auth.m2m` handler so `/oauth/token` + `/oauth/jwks` are reachable (see how `auth.m2m`/`auth.jwt` bind via `workflows.http` handler or route prefix; `auth_m2m.go` endpoints default `/oauth/token`,`/oauth/jwks`). A `GET /healthz` pipeline.
- **`config/app-b.yaml` (verifier):** `http.server` + `router`; `sso.oidc` module `verifier` with `providers: [{name: app-a, issuer: http://app-a:8080, jwksUri: http://app-a:8080/oauth/jwks, clientId: app-b}]` (**N2: issuer string identical to App A's**). Pipeline `POST /verify`: `step.request_parse` (parse_headers:[Authorization] or body token) → `step.sso_validate_token {provider: app-a, token_source: ...}` → `step.json_response` (claims on valid / 401 on invalid). `GET /healthz` + the verification-console UI route (Task 6).
- **`docker-compose.yml`:** services `app-a` (`auth-xservice-a:scenario-102`, port `18102`), `app-b` (`auth-xservice-b:scenario-102`, port `18112`), `app-b depends_on app-a healthy`. Image-bake (mirror scenario 101 seed Dockerfile: WORKDIR /home/nonroot, plugins → `./data/plugins`, `-config` flag, no leading `server`).
- **`seed/seed.sh`:** cross-compile (`GOOS=linux GOARCH=amd64`) the engine server once + the sso plugin (from `../../workflow-plugin-sso`) into `./data/plugins/workflow-plugin-sso/`; bake one image used by both services (different `-config`); `docker compose up`; wait both `/healthz`.

**Step — verify:** `bash -n seed/seed.sh`; `wfctl validate --plugin-manifest ../../workflow-plugin-sso/plugin.json config/app-a.yaml` and `config/app-b.yaml` → pass.
**Commit:** `test(scenario-102): cross-service asymmetric auth scaffold (App A issuer + App B verifier)`.

### Task 5: curl smoke (deterministic, self-isolating)

**Files:** `test/run.sh` (PASS:/FAIL: prefixes).
Assertions (the genuine cross-service proof):
1. `GET app-a/healthz` + `app-b/healthz` → 200.
2. Obtain ES256 token from App A: `POST app-a:18102/oauth/token` (client_credentials, App A client) → `access_token` (decode header alg=ES256, payload aud=app-b, iss=http://app-a:8080).
3. **Accept:** `POST app-b:18112/verify` Bearer <App A token> → 200 + claims (App B verified it from App A's PUBLIC JWKS — no shared secret).
4. **Reject wrong-key:** a token signed by a different EC key → 401.
5. **Reject aud-mismatch:** a token with `aud != app-b` → 401 (N3-adjacent).
6. **Reject wrong-issuer:** a token with `iss != http://app-a:8080` → 401 (**N3**).
7. **Reject expired/garbage** → 401.
(Tokens for 4-6 minted via a tiny inline helper or a second auth.m2m with a different key/issuer; or `openssl`/`go run` mint. Keep deterministic.)
**Step — verify:** run seed.sh then run.sh → `Results: N passed, 0 failed`.
**Commit:** `test(scenario-102): curl smoke — cross-service accept + wrong-key/aud/issuer/expired reject`.

### Task 6: Browser verification console + Playwright + playwright-cli QA + register

**Files:** `ui/index.html`(+ js) (App B "Verification Console": button fetches an App-A token via App B proxy route or pasted, POSTs `/verify`, renders verified claims vs rejection), `static.fileserver` in `app-b.yaml`; `e2e/tests/scenario-102-cross-service-asymmetric.spec.ts` (Playwright: load console → verify valid token → see claims; verify tampered → see rejection; self-reset if stateful); `test/EXPLORATORY.md` + `test/screenshots/`; `scenarios.json` entry (id 102).

- **Playwright** (committed): drives the console; asserts valid→claims, tampered→rejected. Navigate to `http://localhost:18112`.
- **playwright-cli exploratory QA** (DoD): walk the console (fetch token → verify → claims; tamper → rejected), screenshots → EXPLORATORY.md.
**Step — verify:** Playwright `npx playwright test scenario-102-...` pass; playwright-cli QA screenshots captured.
**Commit:** `test(scenario-102): verification-console UI + Playwright + playwright-cli QA + register`.
**Rollback:** revert PR; remove scenarios.json entry.
**PR 2:** open → CI green + Copilot → admin-merge.

---

## PR 3 — workflow-plugin-auth: use-case matrix + close #41

Repo `/Users/jon/workspace/workflow-plugin-auth` (this worktree's branch, or fresh off main). Independent of PR1/PR2 code but references them; merge last.

### Task 7: Use-case → combination matrix doc

**Files:** `README.md` (new "Auth use cases & combinations" section) + `SPEC.md` §X.
Matrix (use case → module/step combination):
| Use case | Combination |
|---|---|
| Same-app session (symmetric) | `step.auth_jwt_issue` (HS256) + `step.auth_validate` against `auth.jwt` |
| First-run admin bootstrap | `step.auth_bootstrap_redeem` + `step.auth_jwt_issue` (see scenario 101) |
| App-to-app M2M asymmetric (ES256) | issuer `auth.m2m` (ES256 + `/oauth/jwks`) → verifier `sso.oidc` `jwksUri` mode + `step.sso_validate_token` (see scenario 102) |
| Human/browser login (external IDP) | OIDC login (`step.oidc_auth_url`/`callback` or `step.auth_oauth_*`) → `sso.oidc` (discovery) + `step.sso_validate_token`; refresh `step.sso_refresh_token` |
| Enterprise SSO / SCIM | provider plugins (okta/auth0/entra/ory-*/scalekit) via `AuthProviderDescriptor` |
Note the asymmetric/JWKS/refresh coverage explicitly answers #41.

### Task 8: Provider descriptor (only if missing)

Check the provider catalog for an `oauth2_oidc` `AuthProviderDescriptor`; add one (descriptor-only, no runtime auth code) only if absent. If present, skip + note.

### Task 9: PR 3, merge, close #41

- Commit docs (+ design/plan/ADR-0003 already on branch). PR → CI green + Copilot → admin-merge.
- Close #41 with evidence (sso v0.1.7 jwksUri mode + scenario 102 + use-case matrix).
- Post-merge retrospective in `docs/retros/`.
**Rollback:** revert docs PR.

---

## Post-merge follow-ups (file, don't implement)
- workflow-scenarios: fix scenario-84's invalid flat `sso.oidc` config to `providers:[]` (hygiene).
