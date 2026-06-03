# Changelog

## [Unreleased]
### Added
- README verified-status banner per workflow#714 (multi-repo QoL sweep).
- CONTRIBUTING.md, examples/minimal/config.yaml, and GitHub issue/PR templates.
- Admin auth config now exposes a `passkey_auth_enabled` toggle, and auth
  methods policy honors `passkey_auth_enabled=false` without requiring apps to
  clear WebAuthn relying party configuration.

## v0.2.10 (2026-05-27)

### Changed

- Re-release auth admin config contracts from merged `main`.
- Keeps `v0.2.9` intact, which was cut before the PR merge.

## v0.2.9 (2026-05-27)

### Added

- Added strict proto admin config contracts:
  - `step.auth_admin_config_describe`
  - `step.auth_admin_config_validate`
- Admin descriptors expose grouped controls, labels, help text, input types,
  config keys, disabled reasons, and write-only secret configured state.
- Admin validation rejects unsafe auth config patches, including production
  password enablement and zero-primary-method configs when required.

### Security

- Admin describe/validate outputs never echo secret values; outputs return
  sanitized config plus `secret_fields` metadata.

## v0.2.4 (2026-05-13)

### Strict-proto config-field gaps closed (BMW local smoke vs workflow v0.51.5, round 3)

Round 3 closes two OAuth gaps the v0.2.3 sweep missed. Both surfaced when BMW
v0.51.5 strict-proto validation rejected fields BMW supplies via the step's
`config:` block (templates render at runtime, but strict-proto validates Config
at build-time when templates are still unresolved literals):

- `OAuthProviderConfig`: added `string return_to = 11`. BMW's `step.auth_oauth_start`
  passes `return_to: '{{ .return_to }}'` in config. The handler now prefers
  `config.return_to` when non-empty, otherwise falls back to `current.return_to`
  (OAuthProviderInput).
- `OAuthProviderConfig`: added `string access_token = 12`. BMW's
  `step.auth_oauth_userinfo` passes
  `access_token: '{{ index .steps "exchange_code" "access_token" }}'` in config.
  The handler now prefers `config.access_token` when non-empty, otherwise falls
  back to `current.access_token` (OAuthProviderInput).

Both fields remain valid on `OAuthProviderInput` for callers that pass them at
runtime (the v0.2.3 contract). Config-when-non-empty is the new tie-breaker.

### Tests

- `TestOAuthProviderConfig_AcceptsReturnToAndAccessToken` — strict-proto accepts
  the new config fields across all four OAuth step types.
- `TestOAuthStart_UsesReturnToFromConfig`, `TestOAuthStart_ConfigReturnToWinsOverCurrent`,
  `TestOAuthStart_FallsBackToCurrentReturnTo` — handler precedence for `return_to`.
- `TestOAuthUserinfo_UsesAccessTokenFromConfig`,
  `TestOAuthUserinfo_ConfigAccessTokenWinsOverCurrent`,
  `TestOAuthUserinfo_FallsBackToCurrentAccessToken` — handler precedence for
  `access_token` (via httptest userinfo server asserting the Bearer header).

### CI fixture

- `.github/fixtures/workflow-compat.yaml` now exercises `config.return_to` on
  `step.auth_oauth_start` and `config.access_token` on `step.auth_oauth_userinfo`.

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
