# Auth OAuth Extraction Design

## Context

BuyMyWishlist added production-safe authentication in its application plugin:
password auth is disabled in production, Google OAuth can be enabled by
configuration, OAuth tokens are delivered through URL fragments, provider
identity lookup is tenant-scoped, and auth methods are advertised only when
their backing configuration is complete.

Those primitives should not remain BMW-specific. `workflow-plugin-auth` already
owns public passwordless auth surfaces for passkeys, TOTP, magic links, and
credential management, so it is the right public extraction target. The
existing `workflow-plugin-sso` remains useful for enterprise OIDC token
validation and should not become the consumer login policy surface.

## Goals

- Add reusable auth primitives to `workflow-plugin-auth` for method policy,
  OAuth provider config/start/exchange/userinfo, numeric challenge codes, phone
  normalization, and password hash/verify compatibility.
- Keep app-specific storage and account linking in the consuming app YAML or
  app plugin. The public plugin must not silently require BMW's Postgres schema.
- Preserve BMW's security behavior: production disables password auth by
  default, OAuth providers advertise only when configured, `return_to` is
  constrained to same-site paths, OAuth exchange supports PKCE, and verified
  email status is exposed for app policy.
- Update BMW to consume `workflow-plugin-auth` step types instead of
  `step.bmw.*` auth primitives after the plugin release is available.
- Dogfood Workflow/wfctl: validate plugin manifests, app YAML, and runtime
  plugin loading through Workflow tooling where available.

## Non-Goals

- Do not move BMW user creation, tenant linking, `oauth_states` persistence, or
  JWT claim policy into the public plugin in the first extraction.
- Do not implement Facebook, Instagram, X, Bluesky, or SMS provider integrations
  as complete production auth flows in this slice.
- Do not create a second token system that competes with Workflow core
  `auth.jwt`.
- Do not add Twilio as a dependency of `workflow-plugin-auth`; SMS delivery and
  verification should remain provider/plugin-backed.

## Recommended Approach

Extend `workflow-plugin-auth` with provider-neutral primitives and keep
provider side effects explicit. BMW then becomes a consumer of these primitives:
YAML owns storage transitions, Workflow core owns JWT validation, and the auth
plugin owns reusable cryptographic/provider steps.

This is better than moving the code to `workflow-plugin-sso` because BMW's
needs are app-facing registration/login and method discovery. `workflow-plugin-sso`
is shaped around enterprise OIDC validation, Entra, Okta, and generic token
exchange. We can later factor shared OIDC internals if duplication becomes
meaningful.

## Plugin Surface

### Password Compatibility

Add:

- `step.auth_password_hash`
- `step.auth_password_verify`

These exist to help apps migrate away from app-local password code while still
supporting non-production password flows and legacy migration checks. Production
policy remains a consuming-app decision enforced by `step.auth_methods_policy`.

### Challenge Codes

Add:

- `step.auth_challenge_generate`
- `step.auth_challenge_verify`

The generate step emits a short numeric code, an HMAC-SHA256 storage hash, the
normalized destination, and an expiration timestamp. Hashing must require a
signing secret and bind `channel`, `destination`, `tenant_id`, `purpose`, and
`code` so a stored hash cannot be replayed across tenants or auth flows. The
verify step checks a submitted code against the stored hash, expiration, and
attempt limits. The plugin does not store the challenge; apps store it using
their chosen database plugin or provider.

### Phone Normalization

Add:

- `step.auth_normalize_phone`

The first version should handle pragmatic E.164 normalization for US-focused
phone numbers and pass through already-normalized E.164 input. It should report
invalid input without panics. It must emit both generic outputs
(`valid`, `phone_e164`, `country`) and BMW-compatible aliases (`phone`,
`phone_valid`) for migration safety. A later version can add libphonenumber if
international behavior needs stronger validation.

### Method Policy

Add:

- `step.auth_methods_policy`
- `step.auth_methods_response`
- `step.auth_policy_audit`

`step.auth_methods_policy` accepts environment, password settings, passkey
settings, email settings, SMS settings, TOTP settings, and OAuth provider
configuration. It outputs booleans for each method and the enabled OAuth
provider list. Missing, empty, templated, or incomplete configuration disables
the method. Password auth is disabled in production unless an explicit override
is provided for non-production or migration contexts.

`step.auth_methods_response` turns policy output into a stable response shape.
`step.auth_policy_audit` reports production password-policy violations and can
be used in CI or operational checks.

### OAuth

Add:

- `step.auth_oauth_provider_config`
- `step.auth_oauth_start`
- `step.auth_oauth_exchange`
- `step.auth_oauth_userinfo`

The first release supports Google as complete and exposes disabled/incomplete
provider metadata for future providers without advertising them as login-ready.
Provider endpoint URLs must be built in or constrained to expected HTTPS
provider hosts in production. Test endpoint overrides are allowed only when
explicitly marked as test-only to avoid sending OAuth credentials to arbitrary
configured URLs.
Start generates state, optional PKCE verifier/challenge, a constrained
`return_to`, an authorization URL, and expiration. Exchange posts the code to
the provider token endpoint, including `code_verifier` when present. Userinfo
returns provider subject, the BMW-compatible `provider_user` alias, email,
email verification status, name, picture, and raw claims where useful.

The plugin does not store OAuth state. Apps must persist `state`,
`code_verifier`, `return_to`, `provider`, tenant/app context, and expiration in
their own storage, then consume it atomically during callback.

## BMW Migration

After a `workflow-plugin-auth` release is available, BMW should:

- Replace `step.bmw.auth_policy` with `step.auth_methods_policy`.
- Replace `step.bmw.auth_methods_response` with `step.auth_methods_response`.
- Replace `step.bmw.oauth_provider_config`, `step.bmw.oauth_start`,
  `step.bmw.oauth_exchange`, and `step.bmw.oauth_userinfo` with
  `step.auth_oauth_*`.
- Replace `step.bmw.auth_challenge_generate/verify` and
  `step.bmw.normalize_phone` with `step.auth_*` equivalents.
- Keep BMW-specific SQL for `oauth_states`, `users`, `user_identities`, tenant
  scoping, and JWT issuance until a broader app identity abstraction exists.

## Testing And Validation

- Unit test each new step with missing config, invalid inputs, and happy paths.
- Use local HTTP test servers for OAuth token and userinfo exchanges.
- Add wftest integration coverage so the plugin manifest advertises the new
  step types and Workflow can instantiate them in pipelines.
- Verify plugin build with `GOWORK=off go test ./... -count=1`.
- For BMW migration, run `GOWORK=off go test ./bmwplugin/... -count=1`,
  `wfctl validate --skip-unknown-types app.yaml infra.yaml`, and UI build.
- Launch or exercise a representative Workflow plugin load path before merging
  the plugin PR.

## Risks

- Output-name drift can break BMW YAML. New plugin steps should preserve
  BMW-compatible snake_case output names and add aliases only when needed.
- OAuth state security depends on consuming-app storage. Docs and tests must
  show atomic consume semantics, but the plugin should not hide storage choices.
- SMS readiness can be misrepresented if policy only sees generic flags. Policy
  should require both route enablement and provider configuration signals.
- Password hash extraction can look like endorsing passwords. Documentation and
  policy defaults must make production password auth opt-out impossible by
  accident.
- Existing magic-link defaults contain BMW-specific copy and env names. Avoid
  expanding that coupling while adding new generic surfaces.
