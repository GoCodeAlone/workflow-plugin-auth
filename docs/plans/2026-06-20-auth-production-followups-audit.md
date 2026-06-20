# Auth Production Follow-Ups Audit

Issue: GoCodeAlone/workflow-plugin-auth#54

## Context

Cleanup found a stale local branch named `docs/auth-plugin-followups`. Its plan
pre-dated the current admin/auth/admin-identity work and mixed reusable auth
plugin primitives with application/provider-owned side effects. This audit
promotes the still-relevant items into current project state and marks obsolete
or external-owner items explicitly.

## Current Disposition

| Follow-up from stale branch | Current disposition | Evidence |
|---|---|---|
| WebAuthn/passkey config alias alignment | Shipped | `AuthMethodsPolicyConfig`, `AuthAdminConfig`, and admin controls use `webauthn_rp_id`, `webauthn_origin`, and `passkey_auth_enabled`; validation rejects enabled/incomplete passkey config. |
| Google OAuth production controls | Shipped | `step.auth_oauth_provider_config`, `step.auth_oauth_start`, `step.auth_oauth_exchange`, `step.auth_oauth_userinfo`; admin config renders Google controls and descriptor-backed provider controls. |
| Provider-descriptor driven admin UI | Shipped | `step.auth_provider_catalog`, `AuthProviderDescriptor`, and `step.auth_admin_config_describe` consume provider descriptors before legacy Google/Facebook fallback controls. |
| TOTP recovery-code primitive | Shipped | `step.auth_totp_recovery_codes` returns recovery codes and hashes; app persistence and one-time redemption remain consumer-owned. |
| Admin profile/credential/invite surface | Shipped as primitives | `step.auth_admin_identity_describe`, `step.auth_admin_invite_issue`, `step.auth_admin_invite_redeem`, and `step.auth_admin_invite_revoke` expose strict-proto contracts for admin/profile/invite UI wiring. |
| Bootstrap redeem for first admin | Shipped | `step.auth_bootstrap_redeem` is count-gated and closes when the consuming app reports existing credentials. |
| BMW-specific defaults | Superseded | BMW compatibility aliases are retained only at typed boundary tests; defaults belong in consuming app config, not the reusable auth plugin. |
| Magic-link signature semantics | Shipped as provider-neutral primitive | `step.auth_magic_link_generate` and `step.auth_magic_link_verify` sign/hash/verify tokens; app storage and delivery remain external. |
| Email-code composition boundary | Shipped as provider-neutral primitive | `step.auth_challenge_generate` and `step.auth_challenge_verify` produce and verify signed challenge codes; app storage, atomic consume, and delivery remain external. |
| Twilio Verify send/check steps | Do not implement in this plugin | Existing design explicitly says not to add Twilio as an auth plugin dependency. The auth plugin exposes readiness policy fields and challenge primitives; Twilio delivery/check belongs in a provider plugin or host workflow. |

## Boundary Decision

`workflow-plugin-auth` remains a stateless primitive library for credential,
challenge, policy, bootstrap, OAuth, and admin contribution contracts. It must
not own provider side effects such as Twilio network calls, app user tables,
tenant membership persistence, or admin invite storage. Those are composed by
the consuming Workflow app or by provider-specific plugins.

## Follow-Up Owners

| Need | Owner |
|---|---|
| Live admin UI for profile, passkey, OAuth, 2FA, and invite management | Admin plugin shell plus consuming app routes registered via `step.auth_admin_identity_describe` and `step.auth_admin_contribution_describe`. |
| SMS delivery using Twilio Verify | A Twilio/provider plugin or host workflow step that calls Twilio after auth policy gates pass. |
| Persisted invite, user, credential, and tenant membership lifecycle | Consuming app database/workflows; auth plugin only validates and normalizes request/response contracts. |
| Cross-app SSO/OIDC and M2M JWT verification | Workflow engine `auth.m2m`, `workflow-plugin-sso`, and provider plugins; see ADR-0003. |

## Verification

Run:

```sh
GOWORK=off go test ./...
```
