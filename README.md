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
- `step.auth_admin_config_describe`
- `step.auth_admin_config_validate`
- `step.auth_oauth_provider_config`
- `step.auth_oauth_start`
- `step.auth_oauth_exchange`
- `step.auth_oauth_userinfo`
- `step.auth_credential_list`
- `step.auth_credential_revoke`

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
