# Tenant-scoped agent access using the reusable auth stack

Status: proposed source design. No client, key, credential, grant, secret, token,
deployment or persistent permission has been created. Owner activation is held.

## Problem and observed boundary

Jon wants agents to verify saved CMS edits and make authorized preview changes
without repeatedly borrowing his personal admin browser session. On 2026-10-09,
the task-owned Tina browser closed at its original four-hour limit, 13:29 UTC.
The control socket no longer exists. Jon confirmed at 16:03 UTC that he made no
edits/customizations, but that statement does not restore authentication. The
three preferred Facebook links and general Contact paragraph remain staged.
No personal browser profile, cookie, token or credential is an acceptable
replacement. No new login handoff is requested by this design.

Persisted page versions, content digests and durable history can independently
verify **saved** edits. An unchanged DB does not prove that an editor has no
unsaved draft. That needs editor autosave with its own versioned draft record,
or authenticated edit-presence/leases with expiry and explicit uncertainty after
a disconnected client. Presence is advisory; optimistic saves still enforce
the loaded version. History begins when adopted, not retroactively.

## Current reusable components, verified from source

| Component | Available behavior | Relevant limit |
| --- | --- | --- |
| `workflow-plugin-auth/adminidentity` at `abf817c` | Typed human principal/store/session adapters; plugin-owned profile, setup and factor UI | No service-principal grant/exchange lifecycle; a setup-code or human 24-hour session is not agent access |
| Workflow `auth.m2m` at inspected `2235eac` | ES256 issue/JWKS; client-credentials and RFC7523 JWT-bearer assertion grants; configurable expiry; typed `TokenRevocationStore` | It is not RFC8693 token exchange. JWT-bearer copies requested scope without a registered-client ceiling. `Authenticate` alone does not pin issuer/audience or require all proposed claims; revocation-store errors currently do not deny |
| `workflow-plugin-sso` provider composition | Existing auth#41 design selects issuer/JWKS verification through the SSO provider rather than building another IDP | Resource grant/revocation checks are still required; a public key is not a CMS permission |
| `workflow-plugin-authz` / multisite adapters | Signed capability ceiling AND current durable role/tenant membership; platform routes separately protected | Current host accepts its human HS256 sessions and resolves durable human users; an arbitrary M2M token cannot be relabelled as one |
| CMS PR35 at `163de28` | Atomic `expected_version` saves/deletes, draft-preserving conflict behavior, transactional tenant revision ledger | Not installed in current v0.1.7 runtime. The ledger counts mutations but is not a full saved-content/actor history; additive upstream history work is separate |

Source references: `adminidentity/types.go`, `adminidentity/handler.go`,
`README.md` Auth Use Cases, and the existing auth#41 design. Workflow references:
`module/auth_m2m.go` (`handleJWTBearer`, `Authenticate`, `parseTokenClaims`,
`isJTIRevoked`). Host reference: multisite `8d38c3b`,
`cmd/multisite-host/admin_plugin_stack.go` (`IssueSession`, `claimsFromRequest`,
`AuthorizeRequest`, `AuthorizeTenantRequest`) and `admin_plugin_authorization.go`.
These are source observations, not claims that a new exchange is deployed.

The original 2026-06-21 reusable identity/authz architecture remains the rule:
shared auth behavior belongs in plugins/Workflow, with only durable adapters,
tenant/resource policy and route assembly in the consuming host. Preserve locked
provider plans and existing human bootstrap/factor/continuity protections.

## Proposed first grant: exact owner-reviewable authority

Use a distinct service principal, proposed display name `Tina preview assistant`.
Its stable opaque subject is separate from Jon/Tina's human users and credentials.
No `super_admin`, `cms.admin`, platform role or human enrollment is granted.
Default activation is read-only; the two-page write capability is a separately
visible owner checkbox for this already requested correction task.

| Permission | Exact boundary |
| --- | --- |
| `admin:multisite.pages:read` | Read saved pages/versions/templates in preview tenant **234**, slug `tinalangevin-review`; tenant listing is filtered to this tenant. No domains/platform listing |
| Proposed `admin:multisite.pages:history:read` | Read this tenant's saved change records/digests; actor metadata is minimal and authorized. No cross-tenant/auth audit history |
| `admin:multisite.pages:update` plus typed resource/field ceiling | Update only root pages **3 `/rock-metal`** and **6 `/contact`**, only `body_html` and required `expected_version`; retain published status, shells and all other fields. Refuse existing canonical blocks rather than clearing them |
| No create/delete/publish-status permission | New pages, archived rows, other page IDs and schedule/status/template changes require a separate owner-reviewed grant |
| No identity/config/infrastructure permission | Deny users, factors, setup/bootstrap, authz administration, tenant/domain writes, reload, files/bundles, ingest/release, provider APIs, image/deploy, SQL or live Tina tenant |

The existing broad page-update capability cannot enforce this field/page ceiling
by itself. A reusable typed grant-policy hook plus the host's exact tenant/page
and request-field adapter must enforce it **before** the CMS handler and again at
its reusable authorization boundary. No arbitrary header/body actor, email,
role, page ID, tenant ID or caller-requested scope expands a grant.

## Authentication and grant lifecycle

1. Owner approves the exact principal, tenant/page/field ceilings, read/write
   split and finite grant expiry. Proposed grant lifetime: **30 days maximum**,
   with explicit owner renewal; disable/revoke at any time.
2. Owner registers the dedicated workload's **public key** after the reviewed
   implementation is available. Its private signing key stays in the owner's
   OS Keychain or the existing runner's protected secret mechanism. Never put a
   personal cookie/private key in chat, repo files, argv, screenshots or routine
   logs. Key creation/registration and any runner permission change require the
   separate activation approval; none occurs in this source design.
3. Compose the existing ES256 assertion grant with a reusable **registered grant
   policy** before token issue. Assert exact client subject/key/issuer/token-endpoint
   audience, expiry, `iat`, one-use `jti` and maximum assertion age (60 seconds).
   Replay prevention is durable and atomic. Intersect requested scopes with the
   current owner-approved grant; copy no unapproved assertion role/capability.
   Do not mount the current unrestricted JWT-bearer grant as an agent broker.
4. Issue a separate audience-bound agent access token, **15 minutes maximum**,
   carrying stable service subject, grant ID/version, exact issuer and resource
   audience, `iat`, `exp`, `jti` and the approved capability ceiling. No refresh
   token, human cookie or implicit extension. Re-issue only while the finite
   current grant is still active. Store the access token only in the task/runner
   process memory; clear it at completion/expiry.
5. Each resource request verifies exact algorithm/key/issuer/audience and required
   claims, then checks the **current durable** principal/grant version, expiry,
   disabled state, tenant/page/field ceiling and persistent token revocation.
   Missing/unavailable grant or revocation storage fails closed. Removing a
   grant immediately denies existing tokens, including after restart. Existing
   human auth and protected-baseline guards remain separate and unchanged.
6. An owner-facing revoke/expiry/key-rotation view belongs in the reusable auth
   admin surface, backed by typed host adapters. Rotation explicitly registers
   a new public key and revokes the old grant/key version; no silent new identity.

This is an assertion-to-short-lived-token path built on existing components,
not a claimed implementation of RFC8693 or a new home-grown identity provider.
The source gaps in the table must be fixed upstream and tested before activation.
If a protected runner already supplies suitable authenticated workload identity,
its provider may replace key custody only after exact issuer/audience/subject
mapping and owner approval; this design assumes no such connector is available.

## Component ownership and implementation sequence

| Owner | Concrete source work |
| --- | --- |
| Workflow `auth.m2m` | Typed pre-issue registered grant policy; scope/claim ceiling and subject/key binding for assertion grants; strict verifier requirements; durable replay/revocation error handling. Opt-in managed-grant mode preserves existing general consumer behavior |
| `workflow-plugin-auth` | Reusable service-principal grant-management contracts/UI, trusted principal projection, typed grant/replay/audit adapters and conformance tests; avoid copying setup-code/human enrollment |
| `workflow-plugin-authz` | Explicit capability/resource/field policy contracts; deny missing or unknown policy; no role-to-superadmin fallback |
| `workflow-plugin-cms` | Saved content/actor/version/digest history and bounded protected read API; atomic version checks in matched API/editor; unsaved draft/presence separately specified |
| `gocodealone-multisite` | Durable service-grant/replay/revocation adapters; exact tenant234 preview/page/field mapping; matched released plugin pins; explicit schema/auth-continuity adoption and activation UI. No app-specific token issuer |

Do not replace existing human user rows or factor tables with an agent. Service
grants do not satisfy first-admin enrollment or reopen bootstrap. Any new schema,
plugin release, shared-app rollout or continuity-baseline transition needs its
own exact reviewed adoption; the existing clean10→11 CMS ledger admission does
not authorize additional history/agent tables. Retain current store identity,
protected human anchor, domains, three live content pointers and Tina live site.

## Audit and saved-edit evidence

Record issue/reject/revoke/key-change/access/write decisions with stable service
subject, owner authorizer, grant/version, request ID, token-JTI **digest**, tenant,
page, action, expected/actual version and before/after content digest. Record no
token, assertion, key, personal credential, raw auth snapshot or body in auth logs.
CMS's separately protected revision store may retain saved content snapshots;
its actor comes only from a verified principal adapter and its content/history
write is the same transaction. Refused/conflicting writes create no successful
revision. Deletions/tombstones preserve authorized history. History has an explicit
adoption/start marker; prior actor/content history is unavailable, not invented.

Each agent edit starts with fresh saved content/version/digest and ends with
saved readback plus actual authenticated frontend verification. Stale versions
fail with a preserved draft; there is no unconditional retry. An unsaved editor
draft remains a distinct object and is never silently promoted or overwritten
because the current published row was unchanged.

## Acceptance and owner activation gate

Before offering activation, independently review exact source, run registered
Workflow/plugin conformance and mounted host tests with synthetic principals,
then exercise real adapter behavior in task-owned isolated stores. Required
denials: wrong key/issuer/audience/subject/tenant/page/field, missing/expired
claims/grant, excess scope, repeated assertion, revoked key/grant/token, store
failure, human-cookie fallback, users/platform/bootstrap/reload/live routes and
stale saved version. Prove revocation/history across restart and no source or
human auth data mutation. Match API/editor guard versions; do not deploy mixed
old unconditional writers. Hosted QA occurs only after an explicitly authorized
reviewed staging adoption, with no real mail or live-site publication.

**Exact owner activation step:** review and approve the above tenant234 read/history
permissions, optional body-only updates for page3/page6 and finite expiry; then
register the dedicated public workload key through the reviewed reusable auth
surface and its secure custody path. That produces a named revocable grant and
short-lived task access, not a copied personal login. Until the implementation,
adoption and approval exist, the current hosted edit blocker remains authentication.
Source/design approval alone creates no access and authorizes no deployment.
