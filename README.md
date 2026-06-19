# workflow-plugin-auth

> ✅ **Verified** — used in production at **buymywishlist**. This plugin has been validated end-to-end in a merged main-branch wfctl.yaml of an active GoCodeAlone project.

Authentication primitives for Workflow applications.

## Installation

This plugin is marked `private` in the workflow registry, meaning `wfctl plugin install` requires a GitHub token with `read:packages` scope:

```sh
export GH_TOKEN=<your-github-personal-access-token>
wfctl plugin install workflow-plugin-auth
```

The plugin binary itself is distributed via public GitHub Releases — `GH_TOKEN` is only required for the registry lookup step.

## Module Types

- `auth.credential` - WebAuthn/passkey relying-party configuration.

## Step Types

- `step.auth_passkey_begin_register`
- `step.auth_passkey_finish_register`
- `step.auth_passkey_begin_login`
- `step.auth_passkey_finish_login`
- `step.auth_totp_generate_secret`
- `step.auth_totp_verify`
- `step.auth_totp_recovery_codes`
- `step.auth_magic_link_generate`
- `step.auth_magic_link_verify`
- `step.auth_magic_link_send`
- `step.auth_password_hash`
- `step.auth_password_verify`
- `step.auth_challenge_generate`
- `step.auth_challenge_verify`
- `step.auth_normalize_phone`
- `step.auth_methods_policy`
- `step.auth_policy_gate`
- `step.auth_methods_response`
- `step.auth_policy_audit`
- `step.auth_provider_catalog`
- `step.auth_admin_contribution_describe`
- `step.auth_admin_identity_describe`
- `step.auth_admin_invite_issue`
- `step.auth_admin_invite_redeem`
- `step.auth_admin_invite_revoke`
- `step.auth_admin_config_describe`
- `step.auth_admin_config_validate`
- `step.auth_oauth_provider_config`
- `step.auth_oauth_start`
- `step.auth_oauth_exchange`
- `step.auth_oauth_userinfo`
- `step.auth_credential_list`
- `step.auth_credential_revoke`
- `step.auth_bootstrap_redeem`
- `step.auth_jwt_issue`

## First-run Admin Bootstrap

`step.auth_bootstrap_redeem` provides a durable, count-gated first-run admin
code redemption. Bootstrap is OPEN when zero admin credentials exist and CLOSES
permanently once any credential (passkey, google, facebook) is enrolled. The
operator provides a one-time code via the `AUTH_BOOTSTRAP_CODE` environment
variable (≥16 chars; the step enforces this minimum and returns `not_configured`
if shorter).

`step.auth_jwt_issue` mints an HS256 bearer token signed with the shared
`AUTH_JWT_SECRET` (≥32 chars, matching `auth.jwt.Init`). The step enforces V-B8:
the standard claims `sub`, `iat`, `exp`, `iss`, and `jti` are always written by
the step itself and cannot be overridden via the caller `claims` map. The minted
token validates directly against an `auth.jwt` module configured with the same
secret via `step.auth_validate`.

Typical bootstrap flow:
1. Fresh deploy → `GET /admin/bootstrap/status` returns `{open: true}`.
2. Operator redeems the out-of-band code → `POST /admin/bootstrap/redeem` with
   `{code}` → `step.auth_bootstrap_redeem` + `step.auth_jwt_issue` → `{token}`.
3. Super-admin uses the bearer token to enrol a passkey or link SSO.
4. First credential inserted → count ≥ 1 → bootstrap closes permanently.
5. Re-deploy with same DB → still closed. Empty credential store → re-opens
   (break-glass).

Environment variables:
- `AUTH_BOOTSTRAP_CODE` — operator-set one-time code, ≥16 characters.
- `AUTH_JWT_SECRET` — HS256 signing secret shared with `auth.jwt` module, ≥32 characters.

## Password Steps

`step.auth_password_hash` and `step.auth_password_verify` are compatibility
steps for non-production auth flows and migrations. Production applications
should use `step.auth_methods_policy` and `step.auth_policy_audit` to keep
password auth disabled and detect stored password hashes.

## Challenge Codes

`step.auth_challenge_generate` emits a six-digit `code`, `code_hash`,
normalized `destination`, `channel`, and `expires_at`. The hash is
HMAC-SHA256 over `channel`, normalized `destination`, `tenant_id`, `purpose`,
and `code`, using a required `signing_secret`.

The plugin does not persist challenges. Store `code_hash`, `channel`,
`destination`, `tenant_id`, `purpose`, `expires_at`, `attempts`, and
`max_attempts` in the application database. Verify with
`step.auth_challenge_verify`, then atomically mark the challenge used in app
storage.

## Phone Normalization

`step.auth_normalize_phone` normalizes US-style phone input to E.164 and passes
through valid E.164 input. It emits generic outputs (`valid`, `phone_e164`,
`country`) plus BMW-compatible aliases (`phone`, `phone_valid`).

## Auth Method Policy

`step.auth_methods_policy` computes which auth methods are currently available
from configuration. Missing, empty, templated, or incomplete values disable the
method. Password auth is disabled in production even when requested.
SMS code auth requires routes enabled, SMS enabled, `twilio_verify_service_sid`,
and either `twilio_account_sid` plus `twilio_auth_token`, or
`twilio_api_key_sid` plus `twilio_api_key_secret`.

`step.auth_policy_gate` filters a previous policy step before public auth
conditionals or responses use it. It disables email-code auth unless a concrete
`signing_secret` is available, filters OAuth providers to supported
implementations (Google by default), and recomputes `primary_method_count`.
Keep app-specific challenge storage, tenant scoping, identity linking, and JWT
issuance in the consuming app.

`step.auth_methods_response` converts policy output into a stable response
shape. `step.auth_policy_audit` reports production password policy violations
for CI or operational checks.

## Admin Configuration Contracts

`step.auth_admin_contribution_describe` exposes the authentication settings
surface for Workflow admin dashboards.

`step.auth_admin_identity_describe` exposes the reusable identity-management
surface for admin dashboards. It advertises profile, credential, invite, and
bootstrap paths plus permission metadata; it never emits invite tokens, invite
token hashes, OAuth secrets, passkey material, or recovery codes.

`step.auth_admin_invite_issue`, `step.auth_admin_invite_redeem`, and
`step.auth_admin_invite_revoke` provide strict-proto validation contracts for
admin invite flows. They normalize and frame the values that the consuming app
persists. The plugin does not own app SQL, tenant storage, or secret delivery in
this phase.

Invite issue/redeem/revoke steps are intentionally persistence-neutral. They
normalize email addresses, enforce optional role and tenant allowlists, reject
wrong-email redemption, reject already-used or expired invites, and compare the
provided invite token against a stored SHA-256 token hash without echoing either
value in outputs. The consuming app is responsible for generating the token,
storing the hash, marking use/revocation atomically, and delivering the invite
link.

`step.auth_admin_config_describe` exposes a strict proto contract for admin
portals to render authentication settings. It returns grouped controls with
labels, help text, input types, config keys, disabled reasons, and write-only
secret state. Controls map to real plugin config keys consumed by the auth
policy, OAuth, WebAuthn, challenge, and delivery steps.

`step.auth_admin_config_validate` accepts a desired config patch and returns a
sanitized accepted patch plus diagnostics. The plugin validates the patch; the
admin host persists accepted config into Workflow configuration or its own
config store. Secret values are never echoed in outputs. Production password
auth, incomplete passkey settings, incomplete OAuth settings, and zero-primary
method configurations are rejected when applicable.

`step.auth_provider_catalog` merges provider descriptors from auth-provider
plugins. Descriptors advertise provider categories, capabilities, required
config fields, selectable options, admin/app scopes, disabled reasons, and
secret field metadata. `step.auth_admin_config_describe` consumes these
descriptors so admin portals render provider controls dynamically instead of
hard-coding vendor-specific fields in the admin shell or auth plugin. When no
provider descriptors are supplied, the existing Google/Facebook OAuth controls
remain as a compatibility fallback. Provider capabilities are default-deny:
capabilities must set `supported: true` before auth admin or policy code treats
them as usable.

## OAuth

OAuth provider config supports Google and Facebook directly as compatibility
providers. Additional providers should be supplied by provider descriptors from
plugins such as SSO, Okta, Auth0, Entra, Ory, or another provider integration.
Policy advertising remains conservative and only marks providers login-ready
when the configured provider is supported by the current policy path and every
required descriptor field is configured. Instagram, X, and unknown providers
return disabled metadata and are not advertised as login-ready unless a provider
plugin supplies a real descriptor and implementation.

`step.auth_oauth_start` emits `state`, optional PKCE values, `return_to`,
`expires_at`, and `authorization_url`. The plugin does not store OAuth state.
Applications must persist state, code verifier, provider, return path, tenant
or app context, and expiry, then consume the state atomically during callback.

`step.auth_oauth_exchange` exchanges an authorization code for tokens.
`step.auth_oauth_userinfo` fetches normalized user claims and emits both
`provider_subject` and the BMW-compatible `provider_user` alias.

OAuth endpoint URL overrides are intended for tests. In normal operation,
Google endpoint overrides must remain HTTPS URLs on the expected Google hosts.
Insecure local test endpoints require `allow_insecure_test_oauth_endpoints:
true`.

## Auth Use Cases & Combinations

`workflow-plugin-auth` is a library of stateless auth primitives; complete auth
flows are composed from these steps plus the engine's built-in `auth.*` modules
and the provider plugins. Which combination covers which use case:

| Use case | Combination | Demonstrated by |
|---|---|---|
| **Same-app session** (symmetric) | `step.auth_jwt_issue` (HS256) → `step.auth_validate` against an `auth.jwt` module sharing the secret | scenario 101 |
| **First-run admin bootstrap** (durable, passkey/SSO upgrade) | `step.auth_bootstrap_redeem` (count-gated) + `step.auth_jwt_issue` + `step.auth_passkey_*` | scenario 101 |
| **Passkey / passwordless** | `step.auth_passkey_*` (`auth.credential` module) · `step.auth_totp_*` · `step.auth_magic_link_*` | scenario 101 |
| **App-to-app M2M, asymmetric (ES256)** — services verify each other with no shared secret | issuer: engine **`auth.m2m`** (`algorithm: ES256`, `/oauth/token`, `/oauth/jwks`) → verifier: **`sso.oidc`** `jwksUri` mode + `step.sso_validate_token` (`workflow-plugin-sso` ≥ v0.1.8) | **scenario 102** |
| **Human / browser login via external IDP** (Auth0/Okta/Entra/Ory) | OIDC login (`step.auth_oauth_*` or engine `step.oidc_auth_url`/`step.oidc_callback`) → `sso.oidc` (discovery mode) + `step.sso_validate_token`; refresh `step.sso_refresh_token`; exchange `step.sso_token_exchange` | — |
| **Enterprise SSO / SCIM** | provider plugins (`workflow-plugin-{okta,auth0,entra,ory-kratos,ory-hydra,ory-polis,scalekit}`) advertised via `step.auth_provider_catalog` / `AuthProviderDescriptor` | — |
| **Credential management** (list, revoke, delete-min-1) | `step.auth_credential_list` / `step.auth_credential_revoke` + consumer `db_query`/`db_exec` | — |

**Asymmetric cross-service note (issue #41):** the engine's `auth.m2m` module is
the ES256 issuer + JWKS server (no plugin-side IDP is needed or built). A verifying
app reuses `sso.oidc`'s `jwksUri` verify-only mode to validate tokens from the
issuer's published JWKS — no shared secret, no OIDC-discovery requirement. External
IDPs plug in through the same provider pattern. See ADR-0002 / ADR-0003.

## BMW Migration Map

- `step.bmw.auth_policy` -> `step.auth_methods_policy`
- `step.bmw.auth_policy_gate` -> `step.auth_policy_gate`
- `step.bmw.auth_methods_response` -> `step.auth_methods_response`
- `step.bmw.oauth_provider_config` -> `step.auth_oauth_provider_config`
- `step.bmw.oauth_start` -> `step.auth_oauth_start`
- `step.bmw.oauth_exchange` -> `step.auth_oauth_exchange`
- `step.bmw.oauth_userinfo` -> `step.auth_oauth_userinfo`
- `step.bmw.auth_challenge_generate` -> `step.auth_challenge_generate`
- `step.bmw.auth_challenge_verify` -> `step.auth_challenge_verify`
- `step.bmw.normalize_phone` -> `step.auth_normalize_phone`

Keep app-specific SQL, tenant scoping, user identity linking, and JWT issuance
in the consuming app until Workflow has a broader identity abstraction.
