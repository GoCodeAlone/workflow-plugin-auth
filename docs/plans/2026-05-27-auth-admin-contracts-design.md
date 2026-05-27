# Auth Admin Contracts Design

## Goal
Add real workflow-plugin-auth administrative contracts so admin portals can discover, render, validate, and persist auth configuration through Workflow-owned config, not demo-only UI state.

## User Requirements
| id | requirement | design response |
|---|---|---|
| R1 | Admin portal configures real auth plugin behavior | Add strict proto admin describe/validate steps over existing auth config keys. |
| R2 | Passkeys, password disable, OAuth, and other auth modes must be administrable | Descriptor groups expose passkey, password, email code, SMS code, TOTP, Google OAuth, Facebook OAuth controls. |
| R3 | Toggles wired to real plugin config, always | Control `config_key` values map to keys already consumed by `auth_methods_policy`, OAuth, credential module, and send/challenge steps. |
| R4 | Plugin-first; demo is proof only | Scenario consumes contract-shaped API data and applies returned config patches; no scenario-only auth semantics. |
| R5 | Security standard | Secrets redacted, validation fail-closed, production password restrictions preserved, unsafe OAuth endpoints rejected unless explicitly configured for tests. |
| R6 | Releases generated after tested/proven | Bump plugin manifest to next version, validate contract, tag release after verification. |

## Global Design Guidance
Source: workspace `AGENTS.md`, `SPEC.md`, `README.md`.

| guidance | response |
|---|---|
| Prefer Workflow/plugin ownership boundaries | Auth plugin owns auth contracts and validation; admin/dashboard owns rendering and persistence orchestration. |
| Avoid stubs/TODO-only/partial wires | New admin controls bind to existing executable config keys; unsupported modes are marked unavailable rather than shown as functional. |
| Strict proto contracts | New admin steps have generated protobuf messages, runtime registry descriptors, and `plugin.contracts.json` entries. |
| Security/quality first | Secret redaction tests, unsafe-change tests, production password gating, and no secret echo in describe/validate outputs. |
| Scenario proves platform capability | `workflow-scenarios` gets light UI/API updates that consume the contract-shaped surface and preserve authz enforcement paths. |

## Approaches Considered
| option | summary | trade-off | decision |
|---|---|---|---|
| A | Admin-specific step contracts in auth plugin | Fits existing strict step registry and Workflow DSL; host persists config patch. | Chosen. Minimal new host assumptions; real plugin contract. |
| B | New long-running auth admin service | More direct CRUD semantics; heavier lifecycle/discovery surface than current plugin precedent. | Rejected for now; no existing service pattern in this repo. |
| C | Keep admin UI-owned JSON schema | Fast UI iteration; duplicates plugin truth and can drift. | Rejected; violates plugin-first/no-fake requirement. |

## Architecture
| component | responsibility |
|---|---|
| `step.auth_admin_config_describe` | Merge plugin config + runtime config + input, return sanitized effective settings, capabilities, control groups, warnings. |
| `step.auth_admin_config_validate` | Accept desired config patch, reject unsafe/incomplete changes, return sanitized accepted patch + effective policy + diagnostics. |
| `AuthAdmin*` proto messages | Stable contract for admin renderers: groups, controls, option lists, diagnostics, secret config state, OAuth provider state. |
| Existing `auth_methods_policy` helpers | Source of truth for which methods are actually enabled. Admin contracts call the same policy path. |
| Scenario admin UI | Renders tabs and labeled controls from contract-shaped JSON; submits patches through scenario API that applies plugin-equivalent validation. |

## Contract Shape
| message | key fields |
|---|---|
| `AuthAdminConfig` | `environment`, passkey keys, email/SMS keys, password toggles, TOTP toggles, OAuth provider client/redirect keys, secret fields. |
| `AuthAdminDescribeInput` | Optional desired environment/context override; no secrets required. |
| `AuthAdminDescribeOutput` | `groups`, `effective_config`, `methods_policy`, `warnings`, `secret_fields`, `error`. |
| `AuthAdminValidateInput` | `desired_config`, `require_primary_method`, optional `allow_secret_placeholders`. |
| `AuthAdminValidateOutput` | `valid`, `accepted_config`, `methods_policy`, `errors`, `warnings`, `secret_fields`, `error`. |
| `AuthAdminControl` | `key`, `label`, `description`, `help_text`, `input_type`, `config_key`, `secret`, `configured`, `required`, `enabled`, `disabled_reason`, `options`. |

Admin update persistence is intentionally not inside workflow-plugin-auth: the plugin validates and returns a config patch. The host/admin plugin writes that patch into Workflow config or its chosen config store. This avoids fake persistence and keeps declarative Workflow config as source of truth.

## Security Review
| risk | mitigation |
|---|---|
| Secret disclosure through admin describe/validate | Secret values are never returned; outputs expose `configured=true/false` and `secret_fields`. |
| Admin enables zero primary login methods | Validation rejects when `require_primary_method=true` and policy result has `primary_method_count=0`. |
| Password auth in production | Existing production block stays authoritative; admin validate returns error/warning instead of enabling passwords. |
| OAuth SSRF / malicious endpoints | Existing OAuth endpoint validation preserved; insecure test endpoints require `allow_insecure_test_oauth_endpoints=true`. |
| Confused UI labels cause unsafe changes | Controls carry labels, descriptions, help text, disabled reasons, and group context. |
| Demo bypasses auth/authz semantics | Scenario admin endpoint remains behind login/session and admin scope; UI only proves contract consumption. |

## Infrastructure Impact
| area | impact |
|---|---|
| Cloud resources | None. |
| Secrets | Existing auth secrets may be configured through host; plugin only validates presence/redacts values. |
| Network | No new network listeners; release workflow/tag push after verification. |
| Plugin loading | New step types require manifest/contract update; validate with `wfctl plugin validate-contract --for-publish`. |
| Runtime | Existing apps can ignore new step types; backward-compatible additive contract. |

## Multi-Component Validation
| boundary | proof |
|---|---|
| Plugin proto ↔ runtime registry ↔ manifest | `GOWORK=off go test ./...`, contract registry test, `wfctl plugin validate-contract --for-publish --tag v0.2.9 .`. |
| Admin contract ↔ auth policy | Unit tests assert describe/validate mirrors `auth_methods_policy` for passkey/password/OAuth/TOTP/SMS/email. |
| Plugin contract ↔ scenario UI | Scenario API returns contract-shaped payload; Playwright exploratory QA verifies controls render/select/update and auth gate still blocks anonymous admin. |
| Release | Manifest version bumped, local checks pass, tag pushed to trigger release workflow. |

## Assumptions
| id | assumption | challenge | fallback |
|---|---|---|---|
| A1 | Admin plugin/host can persist accepted config patches | Host persistence may not exist yet | Contract returns patch and diagnostics only; scenario uses in-memory/demo persistence as consumer proof, not plugin persistence. |
| A2 | Step contracts are the right current extension point | Future Workflow may prefer service contracts | Additive step types can coexist; service wrapper can call same helpers later. |
| A3 | Google/Facebook are the only real OAuth providers currently implemented | Proto has Instagram/X secret fields but runtime says disabled | Descriptor marks unsupported providers unavailable until real runtime support exists. |
| A4 | Password support remains allowed outside production | Some apps may forbid passwords everywhere | Admin config can set `password_auth_enabled=false`; future host policy can impose stricter constraints via input. |

## Self-Challenge
| doubt | answer |
|---|---|
| Could this be just JSON schema in the admin UI? | That would drift from plugin behavior and violates plugin-first requirement. |
| Does validate imply persistence? | No; output is an accepted patch. Persistence belongs to Workflow config/admin host. |
| Is this too broad? | Scope stays to existing auth modes; no new auth providers or credential stores are added. |

## Rollback
| change | rollback |
|---|---|
| Plugin code/contracts | Revert feature commits; old step types remain unchanged. |
| Manifest/version bump | Revert manifest/contract changes or publish a follow-up tag pointing at rollback commit. |
| Scenario UI/API proof | Revert scenario commits; plugin contract remains independently usable. |
| Release tag | If tag is pushed and bad, publish next patch tag with rollback/fix; do not delete public release tags. |

## Adversarial Design Review
### Report
**Phase:** design  
**Artifact:** `docs/plans/2026-05-27-auth-admin-contracts-design.md`  
**Status:** PASS

| sev | class | loc | issue | fix |
|---|---|---|---|---|
| Minor | Simpler alternative | Approach C | UI-only schema is simpler but rejected due user requirement. | Keep rejection explicit. |
| Minor | Infrastructure | Release | Tag push has external release effect. | Gate tag on local contract/test proof and use next patch tag rollback. |
| Minor | Multi-component validation | Scenario | Scenario cannot prove actual host persistence. | Limit claim to contract consumption; plugin validates patch, host persistence out of contract. |

### Bug-Class Scan
| class | result | note |
|---|---|---|
| Project-guidance conflicts | Clean | Plugin-first ownership follows workspace and repo guidance. |
| Assumptions under attack | Clean | Persistence and provider support assumptions listed with fallback. |
| Repo-precedent conflicts | Clean | New surface uses existing strict step contract pattern. |
| YAGNI | Clean | No new auth provider/runtime store introduced. |
| Missing failure modes | Clean | Secret redaction, zero-primary, production password, OAuth endpoint abuse covered. |
| Security/privacy | Clean | No secret echo; fail-closed validation. |
| Infrastructure impact | Clean | Release/tag impact stated; no infra resource changes. |
| Multi-component validation | Clean | Plugin registry/manifest and scenario UI proof included. |
| Rollback | Clean | Runtime/release rollback path stated. |
| User-intent drift | Clean | Directly targets real plugin contracts and scenario proof. |

