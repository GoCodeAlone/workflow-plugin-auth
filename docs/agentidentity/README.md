# Scoped agents for preview sites

`agentidentity` is an opt-in native Go surface, like `adminidentity`; it does not
add gRPC step/manifest claims. Shared behavior belongs here. Hosts provide current
human-owner authorization, durable SQL adapters, canonical route/current-row
resolution and Workflow's managed issuer. No tenant/page IDs are compiled into
the mechanism. The JSON [two-site example](tenants.example.json) is public policy,
not a grant, secret, token or deployed configuration.

## Configure once, approve each site

Construct `NewTenantPolicy` from per-preview `TenantConfig` entries. Each declares
tenant ID, exact API audience/pages/history routes, maximum read/history/body-edit
scopes, allowed root page IDs, and separately approved view audience/origin/paths.
The `NewService` constructor requires that policy, durable Store, trusted ES256
issuer public keys, managed Issuer and Auditor. Missing adapters fail closed.
An unconfigured tenant, unknown scope, misclassified route, alias or page outside
the field/page ceiling is denied. Never include a live tenant in this assistant
configuration. Configuration is a ceiling; it does not enroll an assistant.

API tokens and protected-view tokens use distinct pinned audiences. Assertions
use only registered public P-256 keys, exact issuer/subject/key/endpoint audience,
required issue/expiry/JTI and a60-second maximum. An assertion identity is consumed
once across tenant grants and permission versions, with durable atomic current-
grant checks. Caller assertion roles/extra claims are not forwarded. Tokens last
at most15minutes and never outlive their finite grant (at most30days). Every use
checks the current grant/version/expiry/revoke and token revocation; storage or
audit failure denies. No refresh, client secret, human cookie or HS256 fallback
exists on the exchange path.

`Authorize` accepts a typed Resource built from real host route resolution and
the current saved row, not caller X-Tenant/actor headers or JSON. Body writes
require PUT, the granted root page, exactly `body_html`, positive loaded
`expected_version` and no canonical blocks. The CMS performs atomic CAS; this
library cannot manufacture one. Reads cannot become writes, and no create/delete,
publish-status, schedule, identity, bootstrap, platform, domain, reload or live
authority is supported. Preview access permits exact-origin GET/HEAD only on
declared paths and never forwards a token to another origin.

## Workflow issuer adapter

The dedicated Workflow M2M instance needs the reviewed `IssueManagedToken` API
(WorkflowPR1043), a separately approved stable PEM-loaded ES256 key and
`SetManagedOnly(true)` before serving. Do not expose legacy OAuth grants beside
it or share its key with a legacy issuer. The host maps an `IssuerFunc` directly:

```go
issuer := agentidentity.IssuerFunc(func(ctx context.Context, r agentidentity.IssueRequest) (string, error) {
    return managed.IssueManagedToken(ctx, module.ManagedTokenRequest{
        Subject: r.Subject, Audience: r.Audience, GrantID: r.GrantID,
        GrantVersion: r.GrantVersion, TenantID: r.TenantID, Scopes: r.Scopes,
        IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
    })
})
```

Pin the released matched Workflow API before compiling this adapter; this
plugin's current dependency is not silently changed to an unreleased branch.
The library verifies the complete issued token against pinned public keys and
expected typed grant before returning it. A wrong issuer/audience/scope/tenant,
human token discriminator or longer expiry cannot escape through a miswired
issuer adapter. Managed JWKS and tokens use the same public-key thumbprint `kid`.
Key rotation is explicit trusted-key configuration plus current grant/version
revocation, never silent key generation. This package is not another issuer/IDP.

## Owner activation path

1. Adopt the independently reviewed matched host/plugin/SQL/issuer configuration
   through the guarded staging lane. Verify existing owner factors, accounts,
   protected hosts and content; service QA cannot substitute for owner login.
2. Use the existing signed-in owner account on the reusable **Agent access** page.
   `ManagementHandler` mounts an optional `PagePath`, API `Path` and pinned
   `OwnerOrigin`. The human `OwnerPolicy` authorizes `propose/list/read/create/revoke`
   for current tenant authority. POSTs require exact Origin/Host and same-origin
   fetch metadata; agent bearers cannot be projected into the human resolver.
   Ordinary owner cookies stay in the browser and are never exported to an agent.
3. Select a configured preview, stable assistant subject and registered public
   workload key. Approve finite expiry and permissions. Read/history are selected
   initially; body edits and protected viewing are separate unchecked options.
   The page shows the exact page/origin boundaries. It rejects private-key PEM.
4. Activate only the separately approved protected workload custody path. Reuse
   one approved workload identity/public key for additional separately approved
   tenant grants when appropriate; each grant can expire/revoke independently.
   A new site requires a policy entry and owner approval, not a source fork,
   duplicate personal credential or per-site private-key hand juggling.
5. Revoke from the same page. The durable store checks the loaded grant version
   and records the change transactionally. Rotation uses a separately approved
   public key/new grant and revokes the old grant; there is no implicit renewal.

For an approved local workload, existing `wfctl secrets set --provider keychain
--service <approved-workload> <KEY_NAME>` offers hidden entry, and `--from-file`
supports an approved securely held PEM. Existing `wfctl env setup`/manifest store
routing can handle approved protected-runner configuration where the installed
version/provider supports it. These are instructions for an approved operator,
not commands this task ran. Never put key contents in argv/chat/repo/URLs, call
`secrets get/export` for handoff, or use random `--auto-gen-keys` as an EC PEM
generator. Issuer/workload keys are separate from the existing human admin HMAC.
If the exact runner/store/key permissions are not approved and supported, retain
the activation blocker rather than guessing a credential or generating a key.

## Adoption and evidence limits

The host must mount the exact TLS exchange path and current durable adapters.
Store replay uniqueness is global for issuer/subject/key/JTI, and its current-grant
test plus consume is one transaction. Management create/revoke uses a durable
transactional audit/outbox; plugin approval logs do not alone prove persistence.
Database schema application is explicit and separate; constructors apply no DDL.
No grant can be created until the human owner policy and persistence are mounted.

The existing CMS Basic alternate-host gate does not accept this token yet. Its
separately reviewed strict service-view integration is required before agent
frontend QA; API activation alone proves no view access. Preserve Basic owner
access, anonymous/wrong-auth warmed-cache denial, no-store/Vary/noindex and
cross-origin token restrictions. Human sessions, bootstrap and protected auth
continuity stay separate. CMS CAS/history/promotion adoption and named live-content
approval remain mandatory; no site creation or grant implicitly publishes content.

Tests use synthetic identities/keys and isolated adapters. Service reconstruction
tests prove use of the authoritative adapter instead of a local revocation cache;
production restart durability needs the real durable adapter and hosted proof.
Saved history can verify persisted edits, not unsaved drafts. Full matched-host,
owner-factor and actual browser QA remain adoption requirements.
