# Retro: Durable First-Run Admin Bootstrap

**PRs:** workflow-plugin-auth#40 (v0.3.0) · workflow-registry#195 · workflow-scenarios#64
**Merged:** 2026-06-02
**Branch:** feat/auth-bootstrap-redeem-2026-06-02 (+ feat/auth-manifest-v0.3.0, feat/scenario-101-auth-admin-bootstrap)
**Design:** docs/plans/2026-06-02-auth-bootstrap-redeem-design.md (rev 4)
**Plan:** docs/plans/2026-06-02-auth-bootstrap-redeem.md
**ADRs:** decisions/0001-bootstrap-redeem-as-stateless-count-gated-step.md, decisions/0002-ship-minimal-hs256-session-issue-step.md
**Issues:** closed #23 (shipped) + #21 (already-implemented, evidence-verified)

## Adversarial-review findings, scored

| Phase | Finding | Sev | Outcome |
|---|---|---|---|
| design c1 | session mint named to `auth.jwt`-as-a-step (didn't exist) | Critical | Prescient — cycle-2 proved it; drove the whole real-step re-grounding |
| design c2 | `step.m2m_token`/`step.auth_required` are schema-only (no runtime factory); MCP `list_step_types` lists schema not runtime | Critical | **Prescient** — biggest catch; led to shipping real `step.auth_jwt_issue` + using real `step.auth_validate` |
| design c1 | count-gate TOCTOU; `ON CONFLICT` insufficient | Critical | Resolved upfront — gate on credential count + idempotent seed; no downstream issue |
| design c3 | reserved-claim override via `claims` map | Critical | Resolved upfront — V-B8 (standard claims always overwrite); code-review + tests confirmed |
| design c1 | no docker-compose+Postgres precedent in scenarios | Important | **Prescient** — every scenario runtime bug (driver, WORKDIR, plugin-dir) landed exactly here |
| design c2 | virtual-authenticator headless unproven | Important | Prescient — needed the spike; full ceremony ultimately passed |
| design c3 | secret floor 16 < engine `auth.jwt.Init` 32 | Important | Resolved upfront — raised to 32 |
| plan | `token_source: ".headers.Authorization"` leading-dot → nil → always-401 | Critical | **Prescient** — caught before scenario authoring; scenario-90 precedent applied |
| plan | test helper `(any,error)` ≠ `(*sdk.StepResult,error)` | Critical | Resolved upfront — inline Execute idiom |
| plan | registry uses `capabilities.stepTypes` not top-level `stepTypes` | Important | Resolved upfront — though the actual `origin/main` path was `plugins/` not `v1/` (see gate-miss) |
| plan | seed needs `GOOS=linux GOARCH=amd64` + image-bake | Important | Prescient — without it the plugin binary wouldn't load in-container |

## Gate misses

| Issue | Gate that missed | Why it slipped | Fix idea |
|---|---|---|---|
| Engine SQL driver is `pgx` not `postgres`; `step.set` needs `values:`; `step.token_revoke` needs `blacklist_module`; container WORKDIR `/home/nonroot` → plugins must bake to `./data/plugins`; entrypoint already=server (leading `server` arg breaks `-config`) | all static gates (design/plan/alignment) | consumer/scenario runtime-config schemas + container layout are only observable by **running** the stack; `wfctl validate` passes them (skip-unknown / shape-only) | runtime-launch-validation early on scenario configs (it DID catch them — these are "found by the right gate", just not by static review). Recurs vs `feedback_wfctl_consumer_ci_checklist`. |
| registry manifest path was `plugins/workflow-plugin-auth/manifest.json` (no `v1/`, no `index.json`) — plan assumed `v1/` from a stale local checkout | plan existence-check | the plan's existence note read a stale local checkout, not `origin/main` | existence checks must target `origin/main`, not the local working copy (recurs vs `feedback_check_tags_and_consumer_validate`). |
| subagent reported Playwright "7/7" but it was DB-state-coupled (failed when re-run after the curl smoke dirtied the DB) | n/a (sub-agent self-report) | green-on-my-machine without isolation | lead trust-boundary verification caught it → fixed with self-resetting test setup (both suites now order-independent). |

## Missed skill activations

| Gate | Fired? | Notes |
|---|---|---|
| brainstorming | yes | |
| adversarial-design-review (design) | yes | 4 cycles (3C+9I → 3C+5I → 1C+3I → 0) |
| writing-plans | yes | |
| adversarial-design-review (plan) | yes | 2 cycles (2C+4I → 0) |
| alignment-check + scope-lock | yes | scope-check PASS; lock applied + verified |
| subagent-driven-development | yes | 1 implementer (PR1) + 1 (scenario UI/Playwright) |
| requesting-code-review | yes | PR1: 2 Important fixed |
| pr-monitoring | yes | bash poll-loop per repo; Copilot: 4 (PR40) + 3 (PR64) addressed+resolved |
| post-merge-retrospective | yes | this doc |

## What worked

- **Adversarial design review caught a fictional foundation before any code:** `step.m2m_token`/`step.auth_required` are schema-only types with no runtime factory (MCP `list_step_types` lists the schema registry, not runtime `StepFactories`). Catching this at design (cycle-2) turned "build on a void" into "ship a real `step.auth_jwt_issue` + use real `step.auth_validate`".
- **Plan-phase review caught the always-401 auth gate** (`token_source` leading-dot) before scenario authoring — pointed at the scenario-90 precedent.
- **Lead trust-boundary verification caught two over-claims:** a subagent "all green" while the tree showed stale-undefined symbols (verified actually-fine), and a subagent "Playwright 7/7" that was DB-state-coupled (fixed with self-isolating tests).
- **Runtime-launch-validation (real docker stack) earned its keep:** every consumer-config gotcha (pgx, step.set `values:`, WORKDIR plugin-dir, token_revoke) only surfaced by booting the real engine+plugin+Postgres.

## What didn't

- **Cycle-1 "verified via MCP `list_step_types`" was wrong** — MCP lists schema types, not runtime-registered steps. Cost a full design cycle. Durable lesson: verify a step exists by grepping `StepFactories()`/`CreateStep` runtime registration, not the schema/MCP listing.
- **Plan existence-check read a stale local checkout** (`v1/plugins/…`) when `origin/main` had `plugins/…`. Existence checks must target the remote default branch.

## Plugin-level follow-ups

- **Recurring (2nd+ occurrence): consumer/runtime-config gotchas pass all static gates.** Same class as `feedback_wfctl_consumer_ci_checklist` (driver names, required config keys, plugin-dir layout). Candidate: extend `adversarial-design-review` Existence/runtime-validity to explicitly require, for any emitted engine/consumer config, a one-line check of (a) the SQL driver name the engine bundles, (b) each step's required config keys, (c) the container plugin-dir/WORKDIR — or an explicit "runtime-launch-validation will cover this" note. One prior retro + this one = trend; worth a concrete bug-class line.
- **New (1st occurrence): "step exists" ≠ "step in MCP/schema list".** If it recurs, add a bug-class note to adversarial-design-review: confirm runtime `StepFactories` registration, not schema listing.

## Project guidance updates

| Guidance file | Change | Reason |
|---|---|---|
| docs/design-guidance.md | no change (absent; Q&A captured in design) | The two durable lessons (runtime-factory ≠ schema-listing; existence-checks target origin/main) are recorded here + in feedback memory; not yet a standing repo-guidance doc. |
