# auth#41 — Cross-Service Asymmetric Auth (Design, 2026-06-02, rev 2)

Issue: GoCodeAlone/workflow-plugin-auth#41 (Phase II IDP). **Determination: reuse the engine + provider plugins; the only genuine gap is a small `jwksUri`-only verify mode in the existing `workflow-plugin-sso` provider — NOT a bespoke IDP.** Then demonstrate + document the composition and close #41.

> **rev 2 (adversarial cycle-1, 3 Critical):** cycle-1 design wrongly claimed `auth.m2m` `trustedKeys[]` + `step.auth_validate` verifies a cross-service token — **FALSE** (`parseTokenClaims`/`Authenticate` uses only the module's OWN `m.publicKey`; `trustedKeys` feed only the jwt-bearer *grant*, `auth_m2m.go:852-855`). And `sso.oidc` requires full OIDC discovery (`oidc.NewProvider`, `oidc.go:98`) — it ignores `jwksUri`, and `auth.m2m` serves no `/.well-known/openid-configuration`, so neither verify path worked. **Resolution:** the real, minimal, provider-pattern-aligned gap is a `jwksUri`-only verifier mode in `sso.oidc` (`oidc.NewRemoteKeySet`+`NewVerifier`). With it, App B verifies App A's ES256 token from App A's published `/oauth/jwks` — genuinely asymmetric, cross-process, no shared secret, no discovery, no mock-OIDC. Also fixes client_credentials-vs-jwt-bearer terminology, refresh scope, aud validation, and drops the invalid scenario-84 "precedent".

## §G — Goal

Make Workflow **fully support cross-service asymmetric (ES256) JWT auth** — multiple Workflow apps verifying each other's tokens (M2M, no browser) and human login via external IDPs — by **reusing** existing components + one small enhancement to the SSO provider, then proving and documenting it. Close #41.

## §C — Constraints / Global Design Guidance

| guidance | response |
|---|---|
| Reuse / use existing provider solutions; don't build our own auth (user) | One ~25-LOC enhancement to the *existing* `sso.oidc` provider (JWKS-URI verify); everything else composed from engine `auth.m2m` + `sso` steps + provider plugins. No new module, no new step type. |
| Provider pattern is the IDP home (2026-05-27 arch) | The fix lives in `workflow-plugin-sso` (the OIDC provider plugin) + uses `AuthProviderDescriptor`. |
| Plugin stays a stateless primitive lib (SPEC C1); bootstrap was the one bespoke primitive | No change to workflow-plugin-auth runtime; it only gains docs (+ provider descriptor if missing). |
| Demo proves it (provider-arch R7) | workflow-scenarios stack demonstrates genuine cross-process asymmetric verify. |

## §I — Capability map (#41 need → component)

| Need | Component | State |
|---|---|---|
| App-to-app **issue** (ES256) + JWKS publication | engine `auth.m2m` (`algorithm: ES256` + `privateKey`/generated; `/oauth/token`; `/oauth/jwks` RFC-7517) | exists |
| Cross-service **verification** from published JWKS (asymmetric, no discovery) | **`workflow-plugin-sso` `sso.oidc` NEW `jwksUri` mode** + `step.sso_validate_token` | **the gap — this design builds it** |
| External-IDP **OIDC verification** (discovery) | `sso.oidc` (discovery path, unchanged) + `step.sso_validate_token` | exists |
| **Refresh** | OIDC plane: `step.sso_refresh_token` (discovery providers). M2M plane: re-issue via `auth.m2m` `/oauth/token` (no refresh token for client_credentials — by design). | exists / documented |
| External-IDP wiring (no bespoke vendor code) | provider pattern: `AuthProviderDescriptor` + okta/auth0/entra/ory-*/scalekit | exists |
| Human/browser login | OIDC login (`step.oidc_auth_url`/`callback` or `step.auth_oauth_*`) → verify via `step.sso_validate_token` | exists (documented) |

### The gap (only new code): `sso.oidc` JWKS-URI verify mode
`InitProvider` (`workflow-plugin-sso/internal/oidc.go:91`) only does `oidc.NewProvider(ctx, issuer)` (discovery). Add: when a provider config sets `jwksUri`, build the verifier via `oidc.NewRemoteKeySet(ctx, jwksUri)` + `oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID: audience, SkipClientIDCheck: audience==""})` — **no discovery required**. `ProviderConfig` gains `JWKSURI` (parsed `getString(raw,"jwksUri")`). In this mode `OAuthCfg.Endpoint` is empty (verify-only; refresh/exchange need the discovery path — documented). go-oidc v3.12.0 has both APIs; `internal/oidc_test.go` already has a `mockOIDCServer` for tests. ~25 LOC + test. Patch release of workflow-plugin-sso.

### Two planes (answers "does a browser user factor in?")
- **M2M / app-to-app** — no browser. App A `auth.m2m` (ES256) mints its own token (the client_credentials secret is App-A-LOCAL — it authenticates the caller to App A's own issuer; it is NOT shared with App B). Cross-service trust is **purely the public JWKS**: App B holds no secret, only fetches App A's `/oauth/jwks`. App B verifies via `step.sso_validate_token` (jwksUri mode).
- **Human / browser** — OIDC login at an external IDP (provider pattern); ID token verified by `step.sso_validate_token` (discovery mode); refresh via `step.sso_refresh_token`.

## §V — What is NOT built (and why)
- ⊥ `auth.idp` module / `step.auth_jwks_serve` / asymmetric `step.auth_jwt_issue` — `auth.m2m` already issues ES256 + serves JWKS.
- ⊥ refresh-token issuance in `auth.m2m` — client_credentials has no refresh by design; OIDC providers issue refresh (`step.sso_refresh_token`).
- ⊥ multi-key verify in `auth.m2m.Authenticate` — out of scope; the SSO JWKS-URI verifier is the cleaner, provider-pattern-aligned path (engine core untouched).

## Deliverables (scope)
1. **workflow-plugin-sso** — `jwksUri` verify mode in `sso.oidc` (`InitProvider` + `ProviderConfig.JWKSURI` + parse) + unit test (verify a token against a remote JWKS via the existing `mockOIDCServer`; reject wrong-key + aud-mismatch) + README + plugin.json/version. Patch release.
2. **workflow-scenarios** — `NN-cross-service-asymmetric-auth` stack (docker-compose, ≥2 engine processes):
   - **App A (issuer)**: `auth.m2m` ES256; `/oauth/token` (client_credentials, App-A-local client) + `/oauth/jwks`. Mints a token (aud=`app-b`).
   - **App B (verifier)**: `sso.oidc` `jwksUri: http://app-a:8080/oauth/jwks`, `issuer`+`audience: app-b`; route gated by `step.sso_validate_token`. Asserts: App A's token **accepted** (verified from App A's PUBLIC key only); token signed by a **different** key **rejected** (proves real asymmetric, not same-key); **aud-mismatch rejected**; expired rejected.
   - **Browser leg (DoD)**: a small "verification console" UI on App B — fetch App A's token, POST to App B's verify route, render verified claims vs rejection — driven by **playwright-cli exploratory QA** + a committed **Playwright** test.
   - curl smoke (deterministic, self-isolating) + Playwright + playwright-cli QA (EXPLORATORY.md + screenshots). Register in `scenarios.json`.
   - **Scenario-config notes (cycle-2 N1/N2/N3, mechanical):** App A's `auth.m2m` client MUST be registered with `claims: {aud: app-b}` (aud flows via `client.Claims` pass-through; `issueToken` doesn't set aud otherwise → go-oidc would reject when App B pins `audience`). App A's `auth.m2m.issuer` and App B's `sso.oidc.issuer` MUST be the identical exact string (go-oidc exact-match on `iss`), e.g. `http://app-a:8080`. curl smoke MUST include a **wrong-issuer rejected** case in addition to wrong-key/aud-mismatch/expired.
3. **workflow-plugin-auth** — **use-case → step/module-combination matrix** in README + SPEC §X (same-app HS256 session · app-to-app M2M asymmetric · external-IDP human OIDC · refresh · enterprise SSO/SCIM → which `auth.m2m`/`sso`/provider combination). Add an `oauth2_oidc` `AuthProviderDescriptor` only if the catalog lacks one. Close #41.

## Security Review
- **Asymmetric cross-service**: App B holds only App A's PUBLIC key (via JWKS); App A's private key never leaves App A. The client_credentials secret is App-A-internal (issuer-local), NOT a cross-service shared secret (rev-2 F4 correction).
- **Audience binding** (F8): App A mints `aud=app-b`; App B's verifier sets `ClientID=app-b` so go-oidc rejects tokens for other audiences; scenario asserts aud-mismatch → 401.
- **Issuer pinning**: verifier pins `issuer`; `oidc.NewVerifier` checks `iss`. Wrong-issuer/wrong-key → reject (asserted).
- **Verify-only mode**: jwksUri mode exposes no token endpoint (no exchange/refresh) — minimal surface.
- **Startup coupling** (F6 mitigation): jwksUri `NewRemoteKeySet` is lazy (fetches on first verify), so App B start does not hard-depend on App A being up at boot (unlike discovery `NewProvider`, which fetches at init).

## Infrastructure Impact
- workflow-plugin-sso: additive config + verify path → **patch release**; registry manifest unchanged (no new step/module type — `jwksUri` is provider config).
- Scenario: isolated docker-compose (App A + App B engine processes); ports `1809x`; no cloud, no external IDP creds (App A is the issuer).
- Rollback: §Rollback.

## Multi-Component Validation
Genuine cross-PROCESS boundary: App A (issuer process) ↔ App B (verifier process) over HTTP, App B fetching App A's JWKS. curl smoke asserts accept(App-A-key)/reject(other-key)/reject(aud)/reject(expired) — proving asymmetric cross-service, not same-key (F6). Playwright + playwright-cli drive the browser verification console. Both self-isolate.

## Assumptions (verified)
1. `auth.m2m` issues ES256 + serves `/oauth/jwks` (verified `auth_m2m.go`); App A can mint a token with `aud` (client_credentials path; confirm aud-setting at runtime, else mint via a configured client with audience).
2. go-oidc v3.12.0 `NewRemoteKeySet`+`NewVerifier` verify ES256 from a JWKS without discovery (standard go-oidc; sso already imports go-oidc v3.12.0).
3. Browser "verification console" satisfies the browser-plane DoD; the human-OIDC-login redirect flow is documented (covered by existing oidc steps), not demoed (no external IDP creds in CI).

## Rollback
| Change | Class | Rollback |
|---|---|---|
| sso jwksUri verify mode | additive code + patch release | revert PR; don't advance tag; discovery path unchanged |
| scenario stack | isolated test asset | revert PR; remove scenarios.json entry |
| auth docs + descriptor | docs/manifest | revert |

## Non-goals / follow-ups
- M2M refresh tokens (client_credentials has none — re-issue); auth.m2m multi-key verify.
- Fix scenario 84's invalid flat `sso.oidc` config (`providers:[]` format) — separate hygiene PR (F3); this design does NOT rely on scenario 84 as a precedent.
- gocodealone-multisite adoption (#54).

## Top doubts (self-challenge)
- D1: jwksUri verify mode must check `aud`+`iss` to be a real gate (not just signature) → set ClientID=audience + pin issuer; scenario asserts both.
- D2: App A minting a token with the right `aud` via client_credentials — verify at runtime; fallback = a configured client with `audience`/`scope` mapping.
- D3: scope grew from "zero code" to "~25 LOC in sso" — but this is the honest minimum to *fully* support cross-service asymmetric verify (cycle-1's zero-code claim was based on a false reuse path); still no bespoke IDP, fits the provider pattern.

## Cycle-1 resolutions
| id | sev | finding | resolution |
|---|---|---|---|
| F1 | Critical | `auth.m2m.Authenticate` ignores trustedKeys → cross-service verify path fictional | verify via `sso.oidc` jwksUri mode (the new gap), not trustedKeys |
| F2 | Critical | `sso.oidc` needs discovery; ignores jwksUri; no mock-OIDC exists | add jwksUri (`NewRemoteKeySet`) mode; App A's `/oauth/jwks` is the JWKS — no mock-OIDC/discovery needed |
| F6 | Critical | demo would prove same-key, not cross-service | App B holds only App A's public JWKS; assert other-key REJECTED |
| F3 | Important | scenario-84 invalid `sso.oidc` config = false precedent | don't rely on it; note + optional separate fix |
| F4 | Important | client_credentials sub=client_id, symmetric secret | clarified: secret is App-A-local; cross-service trust is the public JWKS only |
| F5 | Important | refresh only covers OIDC, not M2M | §I: OIDC=`sso_refresh_token`; M2M=re-issue |
| F8 | Important | aud not validated | App A mints aud=app-b; verifier ClientID=app-b; assert aud-mismatch reject |
| F7 | Minor | provider descriptor maybe YAGNI | add only if catalog lacks oauth2_oidc descriptor |
