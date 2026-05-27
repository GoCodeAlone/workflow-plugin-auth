# workflow-plugin-auth SPEC

General-purpose passwordless + password-optional authentication plugin for the workflow engine.

## §G — Goal

Provide reusable auth primitives: passkeys (WebAuthn), TOTP, magic links, OAuth/SSO, credential management, optional password support. Multiple consumers (multisite host, BMW, ratchet, others) configure which surface they expose.

## §C — Constraints

### C1: General-purpose first

This plugin serves N consumers. Constraints from any single consumer (e.g. gocodealone-multisite "passwordless only") apply via per-instance config, not by deleting code paths.

### C2: Password support is OPT-OUT, not removed

Bcrypt + password endpoints + reset flow REMAIN in the codebase. A consumer disables them via module config `disable_password_auth: true` (default `false`). When `true`:
- `/login` and `/password-reset` HTTP endpoints return 410 Gone (or 404 — TBD via T-AUTH followup)
- `step.auth_password_hash` + `step.auth_password_verify` short-circuit (return `{"disabled": true}`)
- Module factory continues to register credentialModule (other capabilities still work)

The disable knob is per-tenant/per-host. Other consumers keep default and continue using passwords.

### C3: Credential model is N-to-1

One user MAY have N credentials. Supported kinds: `passkey` (WebAuthn), `google` (OAuth), `facebook` (OAuth — deferred per T-AUTH-5), `password` (legacy / opt-in), `totp` (2FA layer, not standalone), `magic-link` (transient).

### C4: Identity unification via verified email

SSO callback finds-or-creates a user keyed by verified email. If user already has a session, the new credential is LINKED to the current user_id. If no session, find_or_create by email.

### C5: Forward-compat with strict gRPC contracts

Manifest + capabilities stay aligned with `wfctl plugin verify-capabilities` (workflow#767) so the plugin's advertised steps match runtime registration.

## §I — Interfaces

### Module types

| Type | Purpose |
|---|---|
| `auth.credential` | Credential lifecycle (passkey register/verify, TOTP, magic-link, optional password). Holds disable_password_auth knob. |

### Step types

Passkey:
- `step.auth_passkey_begin_register`
- `step.auth_passkey_finish_register`
- `step.auth_passkey_begin_login`
- `step.auth_passkey_finish_login`

TOTP:
- `step.auth_totp_generate_secret`
- `step.auth_totp_verify`
- `step.auth_totp_recovery_codes`

Magic link:
- `step.auth_magic_link_generate`
- `step.auth_magic_link_send`
- `step.auth_magic_link_verify`

Password (opt-in via `disable_password_auth: false`):
- `step.auth_password_hash`
- `step.auth_password_verify`

Challenge:
- `step.auth_challenge_generate`
- `step.auth_challenge_verify`

OAuth/SSO:
- `step.auth_oauth_provider_config`
- `step.auth_oauth_start`
- `step.auth_oauth_exchange`
- `step.auth_oauth_userinfo`

Credential management:
- `step.auth_credential_list`
- `step.auth_credential_revoke`

Policy:
- `step.auth_methods_policy` — advertise enabled methods (gates on backing config)
- `step.auth_methods_response` — frame methods in API response
- `step.auth_policy_gate` — pre-handler gate
- `step.auth_policy_audit` — audit trail
- `step.auth_provider_catalog` — merge provider descriptors from auth-provider plugins
- `step.auth_admin_config_describe` — admin-renderable auth config controls
- `step.auth_admin_config_validate` — validate and sanitize admin config patches

Misc:
- `step.auth_normalize_phone`

### Config (module `auth.credential`)

- `disable_password_auth: bool` (default `false`) — see C2
- `rp_id: string` — WebAuthn Relying Party ID (env var pinning per V21)
- `origin: string` — WebAuthn allowed origin
- `oauth_providers.<name>.client_id` / `client_secret` / `authorization_url` / `token_url` / `userinfo_url` / `scopes`
- TBD per per-provider config schema

## §V — Invariants

- V1: ∀ active user → ≥1 active credential. Delete-credential when count = 1 → 409 Conflict.
- V2: credential.kind ∈ known set; unknown → reject at handler.
- V3: OAuth callback verified email = source of truth for user identity.
- V4: Active session present → new credential LINKS to current user_id (not creating new user).
- V5: WebAuthn RP ID + origin pinned to env vars (no silent cross-origin).
- V6: Disable_password_auth=true at module config → password steps return `{"disabled": true}` + endpoints return 410.
- V7: Module-level disable knob, not global — multiple credentialModule instances may differ.
- V8: Admin config describe/validate outputs MUST NOT echo secret values; outputs expose configured state and `secret_fields` only.
- V9: Admin config validation MUST reject production password enablement and zero-primary-method configs when `require_primary_method` is true.
- V10: Admin config controls MUST map to real plugin config keys; no UI-only fake auth toggles.
- V11: Provider-specific admin controls MUST be sourced from `AuthProviderDescriptor` values when descriptors are supplied; vendor-specific Google/Facebook controls are compatibility fallback only.
- V12: Provider descriptors MUST NOT advertise a capability as supported unless the owning provider plugin has a real runtime or management implementation and tests for it; missing `supported` is treated as false.

## §T — Tasks (status as of 2026-05-25)

| Task | Status | Evidence |
|---|---|---|
| T-AUTH-1 disable_password_auth knob | ✅ | `internal/disable_password_test.go`, `module_credential.disablePasswordAuth` |
| T-AUTH-2 Credential model | ⚠️ verify | `step_credential.go` exists; struct shape needs audit |
| T-AUTH-3 WebAuthn/passkey handlers | ✅ | `step_passkey.go` + test |
| T-AUTH-4 Google OAuth | ✅ | `step_oauth.go` (Google URLs + scopes) |
| T-AUTH-5 Facebook OAuth | ❌ | filed as #32 |
| T-AUTH-6 credential-link + delete-min-1 guard | ⚠️ verify | per V1 + V4 |
| T-AUTH-7 identity unification (find_or_create) | ⚠️ verify | per V3 |
| T-AUTH-8 bootstrap-code redeem | ❌ | filed as #23 |
| T-AUTH-9 test matrix | ⚠️ partial | 16 test files |
| T-AUTH-10 SPEC.md backport | ✅ (this doc) | filed as #33 |
| T-AUTH-11 registry manifest update | ✅ | workflow-registry#149 merged |
| T-AUTH-12 admin config contracts | ✅ | `step.auth_admin_config_describe`, `step.auth_admin_config_validate`, strict proto contracts |
| T-AUTH-13 provider catalog contracts | ✅ | `step.auth_provider_catalog`, `AuthProviderDescriptor`, dynamic admin-provider controls |

## §X — References

- Cross-consumer integration tracked in [gocodealone-multisite SPEC §C13/C14/V17-V21](https://github.com/GoCodeAlone/gocodealone-multisite/blob/main/SPEC.md)
- Original BMW extraction: [docs/plans/2026-04-26-auth-oauth-extraction-design.md](docs/plans/2026-04-26-auth-oauth-extraction-design.md)
- Policy gate design: [docs/plans/2026-04-26-auth-policy-gate-design.md](docs/plans/2026-04-26-auth-policy-gate-design.md)
- Admin bootstrap design: [docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md](docs/plans/2026-05-17-admin-bootstrap-and-passkey-upgrade-design.md)
