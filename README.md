# workflow-plugin-auth

Authentication primitives for Workflow applications.

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
- `step.auth_methods_response`
- `step.auth_policy_audit`
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

`step.auth_methods_response` converts policy output into a stable response
shape. `step.auth_policy_audit` reports production password policy violations
for CI or operational checks.

## OAuth

The first OAuth slice supports Google. Other providers currently return disabled
metadata and are not advertised as login-ready.

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
