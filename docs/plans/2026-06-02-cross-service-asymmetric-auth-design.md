# auth#41 — Cross-Service Asymmetric Auth via Reuse (Design, 2026-06-02)

Issue: GoCodeAlone/workflow-plugin-auth#41 (Phase II IDP). **Determination: already supported by existing components — demonstrate + document the composition, do NOT build a bespoke IDP.** ADR-0002 deferred a plugin IDP "until a consumer needs cross-service asymmetric verification"; investigation shows the engine + provider plugins already cover it.

## §G — Goal

Prove and document that Workflow already supports **cross-service asymmetric (ES256) JWT auth** — multiple Workflow apps authenticating to each other (M2M, no browser) AND human login via external IDPs (Ory/Auth0/Entra/Okta) — using **existing** components and the **provider pattern**. Close #41 with a demonstrated, documented reuse story. **Zero bespoke auth modules/steps.**

## §C — Constraints / Global Design Guidance

Guidance: none durable file; from SPEC.md C1-C5 + the 2026-05-27 auth-provider-architecture design (the shipped provider pattern) + user Q&A.

| guidance | response |
|---|---|
| Reuse, don't reimplement; use existing provider solutions (user directive) | Compose engine `auth.m2m` + `workflow-plugin-sso` + provider plugins. No new auth machinery. |
| Provider pattern is the home for IDP/SSO (`AuthProviderDescriptor`, 2026-05-27 arch) | External IDPs wired via provider descriptors (okta/auth0/entra/ory-*/scalekit); generic OIDC via `sso.oidc`. |
| Plugin stays a stateless primitive library (SPEC C1) | Bootstrap was the one bespoke primitive; cross-service/IDP = reuse. |
| Demo proves it (provider-arch R7) | A workflow-scenarios stack demonstrates the composition end-to-end. |

## §I — Capability map (#41 need → existing component)

| Need | Reused component | Verified |
|---|---|---|
| App-to-app async **issue** (ES256 asymmetric) + key publication | engine `auth.m2m` (`GenerateECDSAKey`, `/oauth/token` client_credentials/jwt-bearer, `/oauth/jwks`) | `module/auth_m2m.go` |
| Cross-service **verification** (M2M, in-pipeline) | `auth.m2m` `trustedKeys[]` (issuer+publicKeyPEM) + `step.auth_validate` | `auth_m2m.go:236`, `pipeline_step_auth_validate.go` |
| External-IDP **OIDC verification** (asymmetric, JWKS discovery) | `workflow-plugin-sso` `sso.oidc` + `step.sso_validate_token` (go-oidc `IDTokenVerifier`, `issuer`/`jwksUri`) | `workflow-plugin-sso/internal/{oidc.go,step_validate_token.go}` |
| **Refresh tokens** | `step.sso_refresh_token` | `workflow-plugin-sso/internal/step_refresh_token.go` |
| **Token exchange / userinfo** | `step.sso_token_exchange` / `step.sso_userinfo` | sso |
| External-IDP wiring (no bespoke vendor code) | provider pattern: `AuthProviderDescriptor` + `step.auth_provider_catalog` + okta/auth0/entra/ory-*/scalekit plugins | `internal/step_provider_catalog.go` |
| Human/browser login plane | OIDC login (engine `step.oidc_auth_url`/`step.oidc_callback` or plugin `step.auth_oauth_*`) → verify via `step.sso_validate_token` | engine + plugin |

### Two planes (answers "does a browser user factor in?")
- **M2M / app-to-app** — no browser. `auth.m2m` issues ES256 (client_credentials); the consumer app verifies with `step.auth_validate` against an `auth.m2m` holding the issuer's public key as a `trustedKeys` entry. Cross-service asymmetric, fully headless.
- **Human / browser** — OIDC login against an external IDP (provider pattern); the resulting ID token is verified by `step.sso_validate_token` (`sso.oidc`, JWKS). Refresh via `step.sso_refresh_token`.

Both are existing; the plugin adds neither.

## §V — What is NOT built (and why)

- ⊥ `auth.idp` module — engine `auth.m2m` already is the asymmetric issuer + JWKS server.
- ⊥ `step.auth_jwks_serve` — `auth.m2m` `/oauth/jwks` already serves RFC-7517 JWKS for its ES256 key.
- ⊥ asymmetric `step.auth_jwt_issue` — `auth.m2m` is the canonical ES256 issuer; the plugin's HS256 `auth_jwt_issue` stays the symmetric same-app session primitive (v0.3.0).
- ⊥ `step.auth_refresh_token_*` — `step.sso_refresh_token` exists.
Building any of these = duplicating the engine/provider plugins (explicitly rejected by user direction + provider-arch option A/B).

## Deliverables (scope)

1. **workflow-scenarios demo** — `NN-cross-service-asymmetric-auth` admin stack proving the composition end-to-end:
   - **App A (issuer)**: `auth.m2m` ES256, exposes `/oauth/token` (client_credentials) + `/oauth/jwks`.
   - **App B (verifier)**: pipeline route gated by `step.auth_validate` against App B's `auth.m2m` configured with App A's public key as a `trustedKeys` entry — accepts App A's ES256 token (cross-service), rejects tampered / wrong-issuer / expired.
   - **External-IDP / OIDC leg**: `sso.oidc` + `step.sso_validate_token` verifying an OIDC ID token from a mock OIDC issuer (issuer+jwksUri); `step.sso_refresh_token` refresh.
   - **Browser leg (DoD)**: a small "verification console" UI — fetch/obtain a token, POST to App B's verify route, render verified claims vs rejection — driven by **playwright-cli exploratory QA** + a committed **Playwright** test.
   - curl smoke (deterministic, self-isolating) + Playwright + playwright-cli QA (EXPLORATORY.md + screenshots). Register in `scenarios.json`.
2. **Plugin use-case documentation** (workflow-plugin-auth README + SPEC §X) — a **use-case → step/module-combination matrix**: which combination covers (a) same-app HS256 session, (b) app-to-app M2M asymmetric, (c) external-IDP human OIDC login, (d) refresh, (e) enterprise SSO/SCIM — pointing at `auth.m2m`/`sso`/provider plugins. This is the "document what use cases are covered and by what combinations" deliverable.
3. **Provider descriptor** — add an `oauth2_oidc` / `m2m` `AuthProviderDescriptor` to the catalog only if absent (descriptor-only, no runtime auth code).
4. **Close #41** with the demonstrated evidence.

## Security Review
- Asymmetric verification means verifier apps hold only PUBLIC keys (no shared secret) — the whole point; least-privilege across services.
- `trustedKeys` entries are public keys (non-secret); issuer private key stays in the issuer app (env/secrets). JWKS exposes only the public key.
- `step.auth_validate` / `step.sso_validate_token` reject on signature/issuer/audience/expiry mismatch (verified server-side). Scenario asserts tampered + wrong-issuer rejection.
- No new attack surface — composition of existing, contract-tested steps.

## Infrastructure Impact
- No plugin release strictly required (docs + descriptor only). If a provider descriptor is added → workflow-plugin-auth patch release + registry manifest bump.
- Scenario: isolated docker-compose (2 engine apps + mock OIDC issuer); own port range; no cloud.
- Rollback: revert scenario PR (remove from scenarios.json); revert docs PR; no runtime consumers affected.

## Multi-Component Validation
Real boundary: **App A (issuer) ↔ App B (verifier)** across process boundaries via ES256 + JWKS, plus **app ↔ external OIDC issuer**. curl smoke proves cross-service accept/reject deterministically; Playwright + playwright-cli prove the browser verification console; both self-isolate.

## Assumptions
1. `auth.m2m` `trustedKeys[]` config + ES256 issue + `/oauth/jwks` work as read in source (verify at runtime in the scenario).
2. `sso.oidc` verifies via `issuer`+`jwksUri` against a mock OIDC issuer that serves discovery/JWKS (scenario 84 precedent uses sso.oidc against a real issuer). *If the mock-OIDC-with-discovery proves heavy:* the external-IDP leg falls back to verifying App A's `auth.m2m` token via `sso.oidc` `jwksUri=App A /oauth/jwks` OR documents the OIDC leg with the M2M leg as the proven core.
3. A browser "verification console" satisfies the browser-plane DoD without a full external-IDP login UI (the human-OIDC-login UI is documented; the console demonstrates verification visibly).

## Rollback
| Change | Class | Rollback |
|---|---|---|
| scenario (docker-compose stack) | isolated test asset | revert PR; remove scenarios.json entry |
| provider descriptor (if added) | manifest data + patch release | revert; don't advance tag |
| docs (README/SPEC) | docs | revert |

## Non-goals / follow-ups
- Refresh-token issuance by `auth.m2m` (it consumes/validates; OIDC providers issue refresh) — not needed; `step.sso_refresh_token` covers the consumer path.
- gocodealone-multisite adoption — tracked separately (#54).

## Top doubts (self-challenge)
- D1: app-to-app verify path — `auth.m2m` trusted-keys (chosen, direct) vs `sso.oidc` (needs discovery/jwksUri). Resolved: trusted-keys for M2M leg; validated at runtime.
- D2: mock OIDC issuer for the external-IDP leg may be heavy → Assumption 2 fallback keeps the proven core (M2M) intact.
- D3: "zero new code" under-delivers #41? No — the value is the *proven + documented* composition + correct closure; building would duplicate the engine/providers (user-rejected).
