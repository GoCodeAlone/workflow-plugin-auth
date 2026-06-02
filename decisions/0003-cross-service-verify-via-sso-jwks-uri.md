# 0003. Cross-service asymmetric verify via sso.oidc JWKS-URI mode

**Status:** Accepted
**Date:** 2026-06-02
**Decision-makers:** Jon Langevin (codingsloth@pm.me), autodev pipeline
**Related:** `docs/plans/2026-06-02-cross-service-asymmetric-auth-design.md` (rev 2), issue #41, ADR-0002, adversarial cycle-1 (F1/F2/F6)

## Context

#41 asks for cross-service asymmetric (ES256) JWT auth between Workflow apps + external IDPs, using the provider pattern (no bespoke IDP). Investigation: engine `auth.m2m` already issues ES256 + serves `/oauth/jwks`. But the verify side was the gap — adversarial review proved `auth.m2m.Authenticate()` verifies only with the module's OWN key (`trustedKeys` feed only the jwt-bearer grant), and `workflow-plugin-sso`'s `sso.oidc` only verifies via full OIDC discovery (`oidc.NewProvider`), which `auth.m2m` does not serve. So no existing path lets App B verify App A's ES256 token from App A's published JWKS.

## Decision

Add a **`jwksUri`-only verifier mode** to the existing `workflow-plugin-sso` `sso.oidc` provider: when `jwksUri` is configured, build the verifier with go-oidc `NewRemoteKeySet` + `NewVerifier` (issuer + audience pinned), skipping discovery. App B then verifies App A's ES256 token via `step.sso_validate_token` against App A's `/oauth/jwks`. *Alternatives rejected:* (a) add multi-key verification to engine `auth.m2m.Authenticate` — touches engine core for a provider concern, fights the provider pattern; (b) jwt-bearer token exchange (App B exchanges App A's token for a local one) — a token-exchange, not inline verification, and heavier; (c) a bespoke `auth.idp`/JWKS in workflow-plugin-auth — duplicates the engine + the SSO provider (ADR-0002, user-rejected).

## Consequences

- (+) Genuine asymmetric cross-service verification: verifier holds only the public JWKS, no shared secret, no discovery dependency; lazy key fetch avoids boot-order coupling.
- (+) Enhances the existing OIDC provider plugin (provider-pattern-aligned); ~25 LOC + test; engine core + workflow-plugin-auth runtime untouched.
- (+) Also serves real external IDPs that lack/limit OIDC discovery (some Entra B2C configs).
- (−) jwksUri mode is verify-only (no token endpoint) → refresh/exchange still require the discovery path (documented).
- (−) Adds a config field + a second init path to `sso.oidc` (small maintenance surface).
