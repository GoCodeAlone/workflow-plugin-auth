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

**Status:** Locked 2026-06-02T11:01:32Z

---

## PR 1 — workflow-plugin-sso: `sso.oidc` jwksUri verify mode

Repo `/Users/jon/workspace/workflow-plugin-sso`, branch off origin/main. `GOWORK=off`.

### Task 1: `jwksUri` verify mode (TDD)

**Files:** Modify `internal/oidc.go` (`ProviderConfig` + `InitProvider`), `internal/module_oidc.go` (config parse); Test `internal/oidc_jwksuri_test.go`.

**Step 1 — failing test** (`internal/oidc_jwksuri_test.go`): use the existing `mockOIDCServer` (it serves `/keys` JWKS + mints **RS256** tokens — that is FINE; `NewRemoteKeySet`+`NewVerifier` are algorithm-agnostic, so this proves the jwksUri *verify mechanism*; ES256 specifically is proven end-to-end in scenario 102 against real `auth.m2m`, cycle-2 F1). Build a provider via `InitProvider(ctx, ProviderConfig{Name:"app-a", Issuer: mock.URL, JWKSURI: mock.URL+"/keys", ClientID:"app-b"})` (note: NO discovery — assert no request hits `/.well-known/openid-configuration`). Assert: `provider.Verifier.Verify(ctx, validToken)` succeeds for a token with `iss=mock.URL`, `aud=app-b`; fails for a token signed by a DIFFERENT key (add a 2nd mock key/server); fails for `aud!=app-b`; fails for `iss!=mock.URL`. (Reuse `oidc_test.go`'s mock token-minting helpers; do NOT extend the mock to ES256 — unneeded.)

**Step 2:** Run `GOWORK=off go test ./internal/ -run JWKSURI -v` → FAIL (JWKSURI field undefined).

**Step 3 — implementation:**
- `internal/oidc.go` `ProviderConfig`: add `JWKSURI string` + `SigningAlgorithms []string` fields.
- `InitProvider`: branch at the top — when `cfg.JWKSURI != ""`:
  ```go
  keySet := oidc.NewRemoteKeySet(ctx, cfg.JWKSURI)
  algs := cfg.SigningAlgorithms
  if len(algs) == 0 {
      algs = []string{"ES256", "RS256"} // CRITICAL (cycle-2 F1): go-oidc NewVerifier defaults to
      // RS256-ONLY when SupportedSigningAlgs is empty (verify.go:317) — it would REJECT auth.m2m's
      // ES256 tokens at runtime. Must include ES256.
  }
  verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
      ClientID:             cfg.ClientID,
      SkipClientIDCheck:    cfg.ClientID == "",
      SupportedSigningAlgs: algs,
  })
  // verify-only: no discovery, no OAuthCfg.Endpoint (refresh/exchange require discovery path)
  return &OIDCProvider{ProviderName: cfg.Name, Issuer: issuer, Verifier: verifier, OAuthCfg: &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: scopesOrDefault(cfg.Scopes)}, ClaimPaths: claimMapOrDefault(cfg.ClaimMapping)}, nil
  ```
  Keep the existing `oidc.NewProvider(ctx, issuer)` discovery path for the `else` (JWKSURI=="") case unchanged.
- `internal/module_oidc.go` provider parse: add `JWKSURI: getString(raw, "jwksUri")` + `SigningAlgorithms: getStringSlice(raw, "signingAlgorithms")` to the `ProviderConfig` built from `raw`.
- **Test note (cycle-2 F1):** the RS256 mock test must pass `SupportedSigningAlgs:["RS256"]` (or rely on the ES256+RS256 default which includes RS256) — assert it explicitly so the RS256 pass is not accidental. ES256 is proven end-to-end in scenario 102 (real auth.m2m + default algs include ES256).

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
- Registry manifest (cycle-2 F4): check `.github/workflows/release.yml` for an automatic registry notify-dispatch; if present, the registry sync is automatic → skip manual edit. Else open a tiny workflow-registry PR bumping the sso manifest version→0.1.7 + downloads (no capabilities change). Verify `gh release view v0.1.7` has assets.

---

## PR 2 — workflow-scenarios: scenario 102 cross-service asymmetric auth

Repo `/Users/jon/workspace/workflow-scenarios`, branch off origin/main. **Depends on PR 1 merged** (builds sso from main). Scenario id **102** (verify against origin/main `scenarios.json`; 101 is taken). Templates: scenario 101 (image-bake seed, self-isolating tests, docker-compose) + 92 (multi-service).

### Task 4: Scenario scaffold — App A (issuer) + App B (verifier)

**Files (under `scenarios/102-cross-service-asymmetric-auth/`):** `scenario.yaml`, `README.md`, `config/app-a.yaml`, `config/app-b.yaml`, `docker-compose.yml`, `seed/seed.sh`.

- **`config/app-a.yaml` (issuer).** GROUNDED config keys (from `plugins/auth/plugin.go` auth.m2m factory):
  ```yaml
  modules:
    - { name: server, type: http.server, config: { address: ":8080" } }
    - { name: router, type: http.router, dependsOn: [server] }
    - name: appissuer
      type: auth.m2m
      config:
        algorithm: ES256          # omit privateKey → module GenerateECDSAKey at init
        issuer: http://app-a:8080  # MUST byte-match App B's provider issuer (N2)
        tokenExpiry: 1h
        clients:
          - { clientId: app-b-caller, clientSecret: ${APP_A_CLIENT_SECRET}, claims: { aud: app-b } }  # aud flows via client.Claims (N1)
      dependsOn: [router]
  workflows:
    http:
      server: server
      router: router
      routes:                      # mount auth.m2m's HTTPHandler (Handle dispatches by path-suffix); scenario-20 `handler:` pattern
        - { method: POST, path: /oauth/token, handler: appissuer }
        - { method: GET,  path: /oauth/jwks,  handler: appissuer }
  pipelines:
    healthz: { trigger: {type: http, config: {path: /healthz, method: GET}}, steps: [{name: ok, type: step.json_response, config: {status: 200, body: {status: ok}}}] }
  ```
  (Do NOT use `step.delegate`/`api.command` — M2MAuthModule is an `HTTPHandler` (has `Handle`, not `ServeHTTP`); the `handler:` route binding via `app.GetService(name,&HTTPHandler)` is the correct, scenario-20-proven mount. cycle-2 F2.)
- **`config/app-b.yaml` (verifier):** `http.server` + `router`; `sso.oidc` module `verifier` with `providers: [{name: app-a, issuer: http://app-a:8080, jwksUri: http://app-a:8080/oauth/jwks, clientId: app-b, signingAlgorithms: [ES256]}]` (**N2: issuer byte-identical to App A's; cycle-2 F1: signingAlgorithms must list ES256**). Pipelines:
  - `POST /verify`: `step.request_parse` (parse_headers:[Authorization]) → `step.sso_validate_token {provider: app-a, token_source: steps.parse.headers.Authorization}` → `step.json_response` (claims on valid / 401 on invalid).
  - `POST /proxy/token` (cycle-2 F5 — browser same-origin token fetch): `step.http_call` to App A `/oauth/token`. NOTE: auth.m2m's token endpoint uses `r.ParseForm()` (form-encoded), but `step.http_call` `body:` map serializes JSON. Send **form-encoded**: set `headers: {Content-Type: application/x-www-form-urlencoded}` + a pre-encoded `body_from`/raw string `grant_type=client_credentials&client_id=...&client_secret=...` (confirm step.http_call raw-body support at impl time; `pipeline_step_http_call.go`). If form-encoding via step.http_call proves awkward, FALL BACK: drop `/proxy/token` and have the Playwright/playwright-cli test fetch the token from App A's published port (`:18102/oauth/token`) out-of-band and supply it to the console's token input (Task 6). Either path keeps the cross-service verify (the console's job) intact.
  - `GET /healthz` + the verification-console UI route (Task 6).
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

**Negative-case tokens (cycle-2 F3, deterministic):** add a tiny Go helper `test/mint-token/main.go` (cross-compiled in `seed/seed.sh` into `./data/mint-token`, or `go run` at test time) that mints an ES256 JWT with flags `-iss -aud -exp -key <pem>`. run.sh uses it to produce: wrong-key (fresh ES256 key), aud-mismatch (`-aud other`), wrong-issuer (`-iss http://evil`), expired (`-exp -1m`) tokens — all deterministic, no second auth.m2m service, no openssl-in-bash. The valid (accept) token comes from App A's real `/oauth/token` (proving the real issuer path).
**Step — verify:** run seed.sh then run.sh → `Results: N passed, 0 failed`.
**Commit:** `test(scenario-102): curl smoke — cross-service accept + wrong-key/aud/issuer/expired reject`.

### Task 6: Browser verification console + Playwright + playwright-cli QA + register

**Files:** `ui/index.html`(+ js) — App B "Verification Console": a **token textarea** + "Fetch from App A" button (calls App B `/proxy/token`; if that's dropped per F5, the test fills the textarea with a token obtained out-of-band) + "Verify" button (POST `/verify` with the token) → renders verified claims (valid) vs rejection (401). `static.fileserver` in `app-b.yaml`; `e2e/tests/scenario-102-cross-service-asymmetric.spec.ts` (Playwright: obtain an App-A ES256 token via App A's published `/oauth/token` in test setup → fill console → Verify → assert claims shown; then tamper the token → Verify → assert rejection shown; stateless so no DB reset needed); `test/EXPLORATORY.md` + `test/screenshots/`; `scenarios.json` entry (id 102).

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
