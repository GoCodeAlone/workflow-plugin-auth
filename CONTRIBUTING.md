# Contributing to workflow-plugin-auth

This plugin is part of the [GoCodeAlone/workflow](https://github.com/GoCodeAlone/workflow) ecosystem.

## Before contributing

Read the [upstream CONTRIBUTING.md](https://github.com/GoCodeAlone/workflow/blob/main/CONTRIBUTING.md) for general conventions, signing, and review expectations.

## Installation note

This plugin is marked `private` in the workflow registry. `wfctl plugin install` requires:

```sh
export GH_TOKEN=<github-personal-access-token-with-read:packages>
wfctl plugin install workflow-plugin-auth
```

## Local development

```sh
git clone https://github.com/GoCodeAlone/workflow-plugin-auth.git
cd workflow-plugin-auth
GOWORK=off go build ./...
GOWORK=off go test ./...
```

## Pull requests

- One feature or bugfix per PR.
- Update CHANGELOG.md with a Keep-a-Changelog entry.
- Add tests covering new behavior.
- Run `GOWORK=off go vet ./...` before pushing.

## Reporting issues

See the issue templates under `.github/ISSUE_TEMPLATE/`.
