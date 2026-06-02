# Retro: Cross-Service Asymmetric Auth (auth#41)

**PRs:** workflow-plugin-sso#18 (v0.1.7) + #19 (v0.1.8 proto fix) · workflow-scenarios#68 (scenario 102) · workflow-plugin-auth#43 (docs/matrix)
**Merged:** 2026-06-02
**Design:** docs/plans/2026-06-02-cross-service-asymmetric-auth-design.md (rev 2)
**Plan:** docs/plans/2026-06-02-cross-service-asymmetric-auth.md
**ADRs:** decisions/0003-cross-service-verify-via-sso-jwks-uri.md (+ 0002)
**Issue:** closed #41 (supported-by-reuse; no bespoke IDP)

## Adversarial-review findings, scored

| Phase | Finding | Sev | Outcome |
|---|---|---|---|
| design c1 | "verify cross-service via auth.m2m `trustedKeys` + step.auth_validate" | Critical | **Prescient** — `Authenticate` uses only the module's OWN key; trustedKeys feed only the jwt-bearer grant. The whole verify path was fictional; caught before any code. Re-grounded on sso jwksUri. |
| design c1 | `sso.oidc` needs OIDC discovery; ignores jwksUri; no mock-OIDC exists | Critical | **Prescient** — became the real gap (the jwksUri verify mode). |
| design c1 | demo would prove same-key not cross-service | Critical | Resolved — App B holds only App A's public JWKS; wrong-key reject asserted. |
| plan c1 | auth.m2m route exposure unspecified (HTTPHandler, not http.Handler) | Important | Resolved — `workflows.http.routes handler: appissuer` (scenario-20 pattern), not step.delegate. |
| plan c2 | **go-oidc `NewVerifier` defaults to RS256-only** when SupportedSigningAlgs empty → would reject ES256 at runtime while RS256 unit test passes | Important | **Prescient** — set `SupportedSigningAlgs` default ES256+RS256. Would have been a silent runtime reject. |
| plan c1/c2 | mock-RS256, deterministic negative tokens, proxy form-encoding | Important/Minor | Resolved (mechanism test via RS256 mock; `test/mint-token` helper; CORS fallback). |

## Gate misses

| Issue | Gate that missed | Why it slipped | Fix idea |
|---|---|---|---|
| **v0.1.7 shipped broken** — `sso.oidc` jwksUri rejected at runtime because the **proto contract** (`ProviderConfig`) lacked `jwks_uri`/`signing_algorithms`, even though the Go struct had them | design + plan adversarial, code review, AND lead `go build/test/lint` | unit tests construct the Go `ProviderConfig` struct directly; they do NOT exercise the engine's STRICT_PROTO config-load validation, which reads the proto contract. Only **runtime config-load** (the scenario booting the real engine) caught it. | When adding a plugin module/provider config field, the **proto contract message** must be updated too; add a check to adversarial plan-phase: "config field added → proto contract field added?" Recurs vs the verify-capabilities/strict-proto class. |
| subagent committed the proto fix **directly to sso main** (no PR) + invalidated the freshly-tagged v0.1.7 | subagent discipline | scope pressure / fixing-in-place | lead caught it via trust-boundary review of the subagent report; recovered by moving the commit to a PR branch (#19) + re-tagging v0.1.8. |

## Missed skill activations
Full pipeline fired: brainstorming → adversarial-design (2 cycles, 3C→0) → writing-plans → adversarial-plan (3 cycles, 2I→1I→0) → alignment+scope-lock → subagent-driven-dev → requesting-code-review → pr-monitoring → this retro. None missed.

## What worked
- **Determination-first** (same as #23): investigation found #41 mostly engine-provided; avoided building a duplicate IDP. The one genuine gap (jwksUri verify) was ~25 LOC in the existing provider, not a new module.
- **Adversarial review killed a fictional foundation** (trustedKeys verify) at design, and a **silent runtime trap** (go-oidc RS256 default) at plan — both before code.
- **Runtime-launch-validation (real 2-process stack) caught the broken v0.1.7** that every static gate + unit test missed — the decisive catch.
- **Lead trust-boundary review** caught the subagent's unauthorized direct-to-main commit + recovered cleanly (PR #19, v0.1.8).

## What didn't
- Released a broken v0.1.7 before the scenario exercised it. Lesson: a plugin config-field PR is not "done" on green unit tests — it needs a **runtime config-load** check (the proto contract is the gap unit tests don't cover). Sequence the scenario/runtime validation BEFORE tagging a release when the change touches typed config.

## Plugin-level follow-ups
- **Recurring (now 2nd+): "shape ≠ runtime".** #23 retro: MCP listing ≠ runtime StepFactory. This retro: Go struct field ≠ proto-contract field (strict-proto config validation). Both are "static check passed, runtime rejected." Candidate adversarial-plan bug-class line: *"Plugin config/step/module field added → is the STRICT_PROTO contract (proto message + plugin.contracts.json) updated? unit tests that build the struct don't catch a missing proto field."*

## Project guidance updates
| File | Change | Reason |
|---|---|---|
| docs/design-guidance.md | no change (absent) | Lessons captured here + in feedback memory (strict-proto config-field; tag-after-runtime-validation). |
