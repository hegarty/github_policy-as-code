# github-security-controller

A policy-as-code GitHub security controller. It audits repositories against
a declarative `security-policy.yaml`, produces a fingerprinted plan of
proposed changes, and applies them only after that plan is approved —
`audit` and `plan` are strictly read-only; `apply` is the only command that
mutates GitHub state, and only for changes recorded in the plan it's given.

It is owner-agnostic: it works against a personal account, an organization,
a single repository, or every non-archived repository an owner has, without
hardcoding any specific account.

## Usage

```
github-security-controller audit --owner OWNER [--policy FILE] [--json]
github-security-controller audit --repo OWNER/NAME [--policy FILE]
github-security-controller plan --owner OWNER [--policy FILE] --out plan.json
github-security-controller apply --plan plan.json
github-security-controller verify --owner OWNER
github-security-controller repo create --owner OWNER --name NAME --visibility public
```

Authentication: set `GITHUB_TOKEN`, or leave it unset to fall back to the
currently authenticated `gh` CLI session (`gh auth token`).

## What it enforces

See [`security-policy.yaml`](./security-policy.yaml) for the full schema.
Baseline controls: pull requests required before merge, GitHub-verified
signed commits, no force-push or deletion on trunk, required status checks
(TruffleHog + CI), review counts that adapt to solo vs. multi-maintainer
repos, TruffleHog installed with pinned-SHA Actions and diff-mode PR
scanning, native secret scanning + push protection, Dependabot, and CodeQL
on eligible public repos.

New rulesets are staged in GitHub's `evaluate` (dry-run) enforcement mode
first; promoting to `active` is a separate, explicitly re-planned step.

## Development

```
go build ./...
go vet ./...
go test ./...
```
