# Changelog

## v0.2.3 (2026-05-13)

### Strict-proto config-field gaps closed (BMW local smoke vs workflow v0.51.5, round 2)

Round 2 closes two gaps the v0.2.2 sweep missed:

- `step.auth_challenge_generate`: replaced `EmptyConfig` with new
  `AuthChallengeGenerateConfig { string signing_secret = 1; int32 ttl_minutes = 2; }`.
  BMW passes both fields in the step's `config:` block; under v0.2.2 they were
  rejected by strict-proto validation because the contract was `EmptyConfig`.
  The handler now falls back to `config.signing_secret` and `config.ttl_minutes`
  when the corresponding input field is empty/zero.
- `AuthPolicyGateConfig`: verified all four BMW-supplied fields (`policy_step`,
  `signing_secret`, `tenant_id`, `required_runtime_keys`) are present and round-trip
  through strict-proto validation. Added `TestAuthPolicyGateConfig_AcceptsAllBMWFields`
  as a regression guard against future field drift.

### Tests

- Added `TestAuthChallengeGenerateConfig_AcceptsSigningSecretAndTTL` (strict-proto
  validation accepts the new config message).
- Added `TestChallengeGenerate_FallsBackToConfigSigningSecret` and
  `TestChallengeGenerate_FallsBackToConfigTTL` (handler honors config fallbacks
  when input does not carry the value).
- Added `TestAuthPolicyGateConfig_AcceptsAllBMWFields` exhaustiveness regression test.

## v0.2.2 (2026-05-13)

### Strict-proto config-field gaps closed (BMW local smoke vs workflow v0.51.5)

- `AuthMethodsPolicyConfig`/`AuthMethodsPolicyInput` (used by `step.auth_methods_policy`
  and `step.auth_policy_audit`): added BMW-supplied fields that the typed proto
  was rejecting under strict-contracts:
  - `jwt_secret` (string, tag 24)
  - `sms_auth_enabled` (optional bool, tag 25) — alongside existing `sms_enabled`
  - `facebook_oauth_client_id`, `facebook_oauth_client_secret` (tags 26-27)
  - `instagram_oauth_client_id`, `instagram_oauth_client_secret` (tags 28-29)
  - `x_oauth_client_id`, `x_oauth_client_secret` (tags 30-31)
- `AuthPolicyGateConfig` (used by `step.auth_policy_gate`): added
  - `tenant_id` (string, tag 6) — BMW supplies this directly in the gate config block
- `step.auth_challenge_verify`: replaced `EmptyConfig` with new
  `AuthChallengeVerifyConfig { string signing_secret = 1; }`. The handler now
  falls back to `config.signing_secret` when input does not carry one.

### Known deferred (BMW yaml bug — does not require plugin change)

- `step.auth_oauth_exchange`: BMW currently passes `code` inside the step's
  `config:` block. The handler reads `code` from `req.Input` (or merged
  `current`) — `code` belongs in `OAuthProviderInput`, not `OAuthProviderConfig`.
  BMW must move it to a runtime input (e.g. `current.code`, supplied via a
  preceding `step.set` from `parse_request.query.code`). No plugin change made.

### CI

- New `.github/workflows/workflow-compat.yml` runs on every PR:
  builds the plugin, installs latest `wfctl` release, and validates a
  minimal smoke pipeline that exercises every plugin step type.
