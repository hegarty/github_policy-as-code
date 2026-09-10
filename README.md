# github-security-controller

A policy-as-code GitHub security controller. It audits repositories against a declarative `security-policy.yaml`, produces a fingerprinted plan of proposed changes, and applies them only after that plan is approved. The goal isn't to hide source code — it's to establish and continuously verify a trusted software supply chain: developer workstation → SSH-authenticated, signed-commit GitHub access → protected trunk → required CI/security checks → protected `main`.

It is **owner-agnostic**: it works against a personal account, an organization, a single repository, or every non-archived repository an owner has, without hardcoding any specific account. See [`SESSION.md`](SESSION.md) for the project's current status and roadmap, and [`docs/adr/`](docs/adr/README.md) for why it's built the way it is.

## How to operate it

```
github-security-controller audit --owner OWNER [--policy FILE] [--json]
github-security-controller audit --repo OWNER/NAME [--policy FILE]
github-security-controller plan --owner OWNER [--policy FILE] --out plan.json
github-security-controller apply --plan plan.json
github-security-controller verify --owner OWNER
github-security-controller repo create --owner OWNER --name NAME --visibility public
```

The normal flow is **audit → plan → review the diff yourself → apply → verify**:

1. `audit` reads live GitHub state and reports findings. Read-only, always.
2. `plan` does the same read, plus computes the exact `Change`s needed to close the gap, and writes a fingerprinted `plan.json`. Still read-only — nothing on GitHub changes yet.
3. You read `plan.json` (or its table output) and decide whether to proceed.
4. `apply --plan plan.json` re-checks live state first — if anything drifted since `plan` ran, it refuses with a staleness error rather than applying against stale assumptions (`--force` overrides this, deliberately not wired into any automated path).
5. `verify` re-audits after applying, to confirm the changes actually took effect the way you expected.

Authentication: set `GITHUB_TOKEN`, or leave it unset to fall back to the currently authenticated `gh` CLI session (`gh auth token`). No token is ever written to disk by this tool or logged.

## What it enforces

See [`security-policy.yaml`](./security-policy.yaml) for the full schema and current defaults. Baseline controls: pull requests required before merge, GitHub-verified signed commits, no force-push or deletion on trunk, required status checks (TruffleHog + CI), a review-count requirement that adapts automatically to solo- vs. multi-maintainer repos (see ADR-0006), TruffleHog installed with pinned-SHA Actions and diff-mode PR scanning (see ADR-0005), native secret scanning + push protection, Dependabot, and CodeQL on eligible public repos (paid features are never auto-enabled on private repos — see ADR-0008).

## What to expect

- **Every mutation is idempotent.** Running `apply` twice against an already-converged repo is a no-op, not an error or a duplicate.
- **Nothing gets silently weakened or deleted.** The controller never removes rulesets, branch protections, collaborators, secrets, deploy keys, webhooks, or credentials on its own, and never bypasses an existing control without it being an explicit, reviewed part of the plan.
- **A brand-new ruleset can't be staged in dry-run mode on every GitHub plan.** GitHub's `evaluate` (report-only) ruleset enforcement mode requires GitHub Enterprise — confirmed against a live `422` response, not assumed. On Free/Pro/Team accounts, `apply` will fail on a policy that requests `evaluate` enforcement; override to `active` for those repos (see ADR-0007) and rely on plan review plus the retained repository-admin bypass actor as the safety net instead.
- **A first-ever run on an empty repository is bootstrapped, not planned.** There's no ruleset to violate before any commits exist, so the initial commit (workflows, module scaffold, etc.) goes straight to the trunk branch once, *before* any ruleset is created — every commit after that goes through the normal PR flow the ruleset then enforces.
- **Some GitHub API calls report success without taking effect.** At least one setting (`secret_scanning_validity_checks`) has been observed returning `HTTP 200` while silently no-op'ing, likely gated behind a paid tier GitHub doesn't surface as an explicit error for that specific field. `apply` currently can't distinguish this from a real success — see ADR-0008 and `SESSION.md`'s known-gaps list.
- **`plan`/`apply` output never contains secret values.** Findings report repository, path, control, severity, and message — never the contents of a detected secret.

## Development

```
go build ./...
go vet ./...
go test ./...
```

Fixtures for policy evaluation live in `testdata/fixtures/` — one JSON `RepoState` snapshot per scenario (compliant, insecure, solo/multi-maintainer, no-commits-yet, unsafe workflow, missing/weakened TruffleHog, bypass-actor drift). `internal/policy/evaluate_test.go` is the clearest concrete spec of what each of those looks like in practice.
