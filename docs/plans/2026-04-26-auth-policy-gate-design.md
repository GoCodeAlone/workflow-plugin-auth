# Auth Policy Gate Design

## Context

BMW currently carries `step.bmw.auth_policy_gate` to adapt `step.auth_methods_policy`
output before public auth endpoints use it. That gate performs two reusable
jobs: it disables email-code auth when no signing secret is actually configured,
and it filters OAuth providers down to provider implementations the auth plugin
can safely support. Keeping that in BMW duplicates auth policy logic and makes
future Workflow apps repeat the same safety checks.

## Decision

Add `step.auth_policy_gate` to `workflow-plugin-auth` next to the existing
policy, response, and audit steps. The step accepts a `policy_step` config value
that names a previous step result to read, plus optional `signing_secret` and
`oauth_supported_providers` config. It emits the same policy-shaped output as
`step.auth_methods_policy` so apps can drop it between policy calculation and
conditionals or `step.auth_methods_response`.

## Requirements

- Preserve structured output types, especially `oauth_providers` as `[]string`.
- Disable `email_code_enabled` when the signing secret is missing, empty, or an
  unresolved template value.
- Filter `oauth_providers` against supported provider names. Default support is
  Google only because that is the only complete OAuth provider in the plugin.
- Recompute `primary_method_count` when email code or OAuth providers are
  removed.
- Fail closed for missing policy step output by emitting disabled booleans,
  empty provider slices, and count zero.
- Register and advertise the step in plugin code, `plugin.json`, and README.
- Keep app-specific tenant, SQL, JWT issuance, and identity linking out of the
  plugin.

## Acceptance Criteria

- Unit tests cover signing-secret gating, OAuth filtering, templated secret
  rejection, missing policy fail-closed behavior, and typed provider output.
- Plugin integration test confirms `step.auth_policy_gate` is listed and
  instantiable.
- `GOWORK=off go test ./...` passes in `workflow-plugin-auth`.
- BMW can later replace `step.bmw.auth_policy_gate` with `step.auth_policy_gate`
  without changing downstream YAML conditionals or response shapes.
