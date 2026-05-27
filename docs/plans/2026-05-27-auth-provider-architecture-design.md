# Auth Provider Architecture Design

## Goal
Make authentication providers plugin-first and dynamically discoverable so the admin portal can configure real auth methods, OIDC/SSO providers, identity-management providers, and enterprise SSO/SCIM providers without hard-coded vendor UI in `workflow-plugin-auth` or `workflow-plugin-admin`.

## User Requirements
| id | requirement | design response |
|---|---|---|
| R1 | Fix the `go vet` issue first | Completed separately in `workflow-plugin-authz` v0.5.8; this design does not reopen it. |
| R2 | Remove hard-coded admin UI coupling | Completed in `workflow-plugin-admin` v1.1.6 for the shell; this design removes auth-provider hard-coding from auth admin contracts. |
| R3 | Support actual auth providers: Okta, Auth0, Entra, Ory Kratos, Ory Hydra, Ory Polis | Add strict provider descriptor contracts in auth core; update existing Okta/SSO plugins; add Auth0, Entra, Kratos, Hydra, and Polis provider plugins with SDK/API-backed implementations. |
| R4 | Distinguish auth categories clearly | Providers declare categories: `identity_management`, `authentication_method`, `oauth2_oidc`, `enterprise_sso`, `directory_sync`, `authorization_provider`, and `transport_auth`. |
| R5 | Do not support only Ory | Each category has non-Ory coverage: local passkey/passwordless auth, generic OIDC, Okta, Auth0, Entra, and Scalekit for enterprise SSO/SCIM where useful. |
| R6 | Admin forms should use lookups, not text entry, when data is known | Admin describe outputs include provider descriptors, capability descriptors, option lists, required config keys, secret flags, and validation endpoints. |
| R7 | Real plugin functionality, demo only proves it | Provider plugins own their contracts and SDK clients. `workflow-scenarios` only composes them and proves admin/runtime behavior. |
| R8 | Generate releases as updates are tested | Each PR group ends with local verification, merge, and patch release for changed plugin repos. |

## Global Design Guidance
Source: workspace `AGENTS.md`, `README.md`, current plugin READMEs/plans.

| guidance | response |
|---|---|
| Prefer Workflow plugin ownership boundaries | Core auth owns shared provider descriptors and auth-method policy; provider plugins own vendor SDKs/APIs; admin owns rendering/navigation only. |
| Avoid stubs, TODO-only implementations, and false functionality | A provider capability is advertised only when backed by code and tests. Unsupported SDK/API surfaces are omitted or explicitly marked unavailable with a reason. |
| Use strict proto contracts | Every cross-plugin descriptor and admin surface has protobuf messages and `plugin.contracts.json` entries. |
| Security and quality first | Secrets are write-only/redacted, provider clients use least-privilege scopes, OAuth/SSO callbacks require PKCE/state validation, and provider management actions are authz-gated by scopes. |
| Dogfood Workflow/wfctl | Scenario composes auth/admin/authz/provider plugins and is validated with `wfctl plugin validate-contract`, scenario tests, and browser QA. |
| Dirty worktrees are normal | Work happens in clean worktrees; existing root checkout dirt is not reverted. |

## Provider Taxonomy
| category | purpose | Ory implementation | non-Ory implementation |
|---|---|---|---|
| `authentication_method` | Passkeys, passwords, TOTP, magic links, challenge delivery | Kratos for identity flows where available | `workflow-plugin-auth` local passkey/TOTP/magic-link steps |
| `identity_management` | Users, identities, credentials, recovery, profile lifecycle | Kratos via official `kratos-client-go` | Okta SDK, Auth0 Go SDK, Microsoft Graph SDK |
| `oauth2_oidc` | OAuth2/OIDC login, token validation, clients, consent/login server | Hydra via official `hydra-client-go` | `workflow-plugin-sso` using `go-oidc`/`oauth2`, Okta/Auth0/Entra OIDC descriptors |
| `enterprise_sso` | SAML/OIDC organization SSO, IdP discovery, B2B onboarding | Polis/Jackson API | Okta, Auth0 enterprise connections, Entra, Scalekit SDK |
| `directory_sync` | SCIM users/groups provisioning/deprovisioning | Polis/Jackson SCIM API | Microsoft Graph, Okta, Auth0, Scalekit SDK |
| `authorization_provider` | RBAC/ABAC/ReBAC evaluation and policy management | Keto already belongs to `workflow-plugin-authz` | Casbin, Permit.io, OpenFGA-style provider if added later |
| `transport_auth` | Protocol-level handshake identity | N/A | `workflow-plugin-ws-auth` HMAC challenge/identity |

## Approaches Considered
| option | summary | trade-off | decision |
|---|---|---|---|
| A | Keep adding vendor fields to `workflow-plugin-auth` | Fast for one provider, but hard-codes UI/contract and grows a monolith. | Rejected; violates pluggability. |
| B | Provider plugins expose admin UI only | UI becomes pluggable, but auth core cannot validate provider choices or produce policy. | Rejected; auth policy still needs provider descriptors. |
| C | Shared provider descriptor contract + provider-owned SDK plugins | Core auth remains generic; provider repos declare capabilities; admin renders dynamic descriptors. | Chosen. |

## Architecture
| component | responsibility |
|---|---|
| `workflow-plugin-auth` | Shared `AuthProviderDescriptor` proto, dynamic admin config describe/validate, auth method policy, built-in local auth descriptors. |
| `workflow-plugin-sso` | Generic OIDC provider runtime and descriptors for generic OIDC, Okta issuer helper, Entra issuer helper, and Auth0 issuer helper. |
| `workflow-plugin-okta` | Okta management-plane SDK client, provider descriptors, user/group/app/auth-server/admin surface contracts. |
| `workflow-plugin-auth0` | Auth0 SDK client, authentication/management descriptors, users/roles/connections/app client operations, OIDC descriptor export. |
| `workflow-plugin-entra` | Microsoft Graph SDK client using Azure/Kiota auth, users/groups/app registrations/auth-method policy descriptors, OIDC descriptor export. |
| `workflow-plugin-ory-kratos` | Kratos client for identity-management and auth-flow descriptors: identities, recovery, verification, passkeys/passwordless if SDK/API supports configured flow settings. |
| `workflow-plugin-ory-hydra` | Hydra client for OAuth2/OIDC server operations: OAuth2 clients, JWKS metadata, consent/login integration descriptors. |
| `workflow-plugin-ory-polis` | Polis/Jackson API client for enterprise SSO and SCIM where no official Go SDK exists; uses official REST/API shape and marks SDK provenance in capability metadata. |
| `workflow-plugin-scalekit` | Non-Ory enterprise SSO/SCIM provider using the official Scalekit Go SDK. |
| `workflow-plugin-admin` | Generic contribution shell only; renders provider/admin surfaces from registered contributions and descriptor JSON. |
| `workflow-scenarios` | Composes the app and admin portal, rotates provider configs, runs runtime/browser tests, and includes tailscale sidecar deployment manifests. |

## Contract Shape
`workflow-plugin-auth` adds shared messages:

| message | purpose |
|---|---|
| `AuthProviderDescriptor` | Provider ID, display name, categories, implementation package, version, docs URL, support level, management base path, auth base path, and capabilities. |
| `AuthProviderCapability` | Capability key, category, supported mode, required scopes, required config keys, secret keys, option lists, default authz scopes, and disabled reason. |
| `AuthProviderConfigField` | UI/admin metadata for a config key: label, description, input type, required, secret, selectable options, validation pattern, and source lookup. |
| `AuthProviderCatalogInput/Output` | Lets workflows merge descriptors from multiple provider plugin steps and pass them into auth admin describe/validate. |
| `AuthAdminConfig.providers` | Dynamic descriptor list consumed by admin describe/validate. Static vendor-specific OAuth controls become compatibility fallback only when no descriptors are supplied. |

Provider plugins expose a `step.<provider>_auth_provider_describe` step returning this descriptor shape. Provider-specific management steps remain in each provider repo and use their own strict proto messages.

## Data Flow
1. App workflow configures provider modules: local auth, SSO OIDC, Okta/Auth0/Entra/Ory/Scalekit as needed.
2. On startup or admin page load, provider descriptor steps run and their outputs are merged by `step.auth_provider_catalog`.
3. Admin dashboard lists dynamic contributions from provider plugins and calls auth admin describe with the merged catalog.
4. Admin UI renders controls from descriptors. Known providers, capabilities, scopes, fields, and option values are selectable, not text-only.
5. Admin submits a config patch. Core auth validates generic auth-method safety; provider plugins validate provider-specific constraints.
6. Host/admin persists accepted patches into Workflow config or an approved config store. Provider plugins never echo secrets.
7. Runtime auth flows call provider runtime steps: local auth, SSO token validation, OAuth exchange/userinfo, or management actions.

## Security Review
| risk | mitigation |
|---|---|
| Provider descriptor lies about capabilities | Runtime tests must exercise each advertised capability; capabilities include support level and disabled reason. |
| Secret disclosure | Secret fields are never returned; outputs include only `configured` and `secret_fields`. |
| Confused deputy between app/admin contexts | Capabilities declare default admin/app scopes separately; admin endpoints require admin scopes before invoking provider actions. |
| OAuth/SSO CSRF or code injection | PKCE/state/nonce validation remains required in app workflow; provider descriptors mark requirements; scenario tests callback abuse cases. |
| SSRF through endpoints | OIDC discovery and endpoint overrides require HTTPS and known-host validation unless explicit local-test flag is set. |
| Overprivileged SDK credentials | Provider configs declare least-privilege default scopes; tests assert dangerous defaults are not silently added. |
| SCIM destructive sync | Directory sync capabilities require explicit write scopes and scenario tests deprovisioning as disabled unless configured. |
| SDK/API drift | Provider SDK versions are pinned; release verification includes `go vet`, tests, contract validation, and runtime launch. |

## Infrastructure Impact
| area | impact |
|---|---|
| Repositories | New repos may be created for Auth0, Entra, Ory Kratos, Ory Hydra, Ory Polis, and Scalekit plugins if absent. |
| Secrets | Scenario uses local/mock provider servers by default; real provider credentials remain env/secret references only. |
| Network | Runtime tests use local test servers; optional real-provider smoke tests run only when credentials are present. |
| Docker/Kubernetes | Scenario deployment includes app, admin, local provider mocks where needed, and a tailscale sidecar using existing cluster secret wiring. |
| Releases | Each changed plugin repo gets a patch release after PR merge and green validation. |

## Multi-Component Validation
| boundary | proof |
|---|---|
| Auth descriptor proto to runtime | Core auth tests create typed descriptors and verify admin describe renders providers dynamically. |
| Provider SDK to plugin | Provider plugin tests use official SDK client types plus httptest servers or SDK mock transports. |
| Provider plugin to auth admin | Scenario runs descriptor merge and verifies provider selectors are populated from provider steps. |
| Admin UI to authz | Browser QA verifies users without admin provider-management scopes cannot see or save provider controls. |
| Runtime enforcement | Scenario rotates generic OIDC/Auth0/Entra/Okta/Ory descriptors and verifies login/token checks use the selected provider. |
| Release | `go test ./...`, `go vet ./...`, `wfctl plugin validate-contract`, scenario run, and Playwright CLI QA before each release. |

## Assumptions
| id | assumption | challenge | fallback |
|---|---|---|---|
| A1 | Provider descriptors can be passed through Workflow step outputs today | A central runtime registry may not exist yet | Use `step.auth_provider_catalog` merge step now; later service registry can call same helpers. |
| A2 | Ory Polis has no stable official Go SDK | If a Go SDK appears, direct HTTP client is less ideal | Keep `sdk_name`/`sdk_url` metadata and switch implementation behind same contract when available. |
| A3 | Real cloud-provider integration tests cannot always run locally | Credentials may not be present | Default to SDK-backed local httptest/mocks; credentialed smoke tests are opt-in and never required for PR CI. |
| A4 | Existing `workflow-plugin-sso` is not redundant | Some OIDC flows belong in generic runtime rather than vendor management plugins | Keep it as generic OIDC runtime and add descriptors/helpers instead of folding it into auth. |
| A5 | Provider admin config persistence belongs outside provider plugins | Some providers can persist remotely | Provider plugins validate/perform remote management actions, but Workflow config persistence remains host-owned. |

## Self-Challenge
| doubt | answer |
|---|---|
| Is this too many plugins? | The user explicitly asked for multiple provider implementations and category clarity. Plugin boundaries prevent a single auth monolith. |
| Could descriptors become another hard-coded schema? | Descriptors are generic and provider-owned; auth core only knows categories/capabilities, not vendor fields. |
| What fails first? | Descriptor/admin mismatch. Tests require every advertised capability to have a provider step, contract entry, and scenario proof before release. |

## Rollback
| change | rollback |
|---|---|
| Core auth descriptor contract | Revert the additive PR or release a patch tag restoring previous admin fallback behavior. |
| Existing provider plugin updates | Revert provider descriptor PRs independently; auth core still supports built-in/local descriptors. |
| New provider plugin repos | Do not install in scenarios; tags can remain but registry entries can be withheld or superseded by patch releases. |
| Scenario deployment | Revert scenario config/manifests; no production deploy is performed without approval. |

## Source Notes
- Okta Go SDK v6 is official and current per `github.com/okta/okta-sdk-golang`.
- Auth0 Go SDK v2 is official for Authentication and Management APIs per `github.com/auth0/go-auth0`.
- Microsoft Graph Go SDK is official for Graph v1.0 and pairs with Azure/Kiota auth per `github.com/microsoftgraph/msgraph-sdk-go`.
- Ory SDK guidance says Ory Network uses `client-go`; self-hosted Kratos/Hydra/Keto use component SDKs matched to deployed versions.
- Ory Polis is the open-source successor to BoxyHQ Jackson and supports SAML/OIDC enterprise SSO and SCIM, but current public materials emphasize REST/service usage rather than a stable Go SDK.

