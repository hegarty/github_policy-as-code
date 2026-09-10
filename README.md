# github-security-controller

A policy-as-code GitHub security controller. It audits repositories against a declarative `security-policy.yaml`, produces a fingerprinted plan of proposed changes, and applies them only after that plan is approved. The goal isn't to hide source code — it's to establish and continuously verify a trusted software supply chain: developer workstation → SSH-authenticated, signed-commit GitHub access → protected trunk → required CI/security checks → protected `main`.

It is **owner-agnostic**: it works against a personal account, an organization, a single repository, or every non-archived repository an owner has, without hardcoding any specific account. See [`SESSION.md`](SESSION.md) for the project's current status and roadmap, and [`docs/adr/`](docs/adr/README.md) for why it's built the way it is.

## Getting started

**1. Install Go 1.22 or newer.** The exact version this project is pinned to is in [`.tool-versions`](.tool-versions) (`golang 1.22.7`). If you use [asdf](https://asdf-vm.com), `asdf install` in the repo root picks it up automatically; otherwise install any Go ≥ 1.22 from [go.dev/dl](https://go.dev/dl/) and confirm with `go version`.

**2. Clone and build the binary.**
```
git clone git@github.com:hegarty/github_policy-as-code.git
cd github_policy-as-code
go build -o github-security-controller ./cmd/github-security-controller
```
This produces a single `github-security-controller` executable in the repo root (gitignored — rebuild after every `git pull` that touches Go source).

**3. Authenticate to GitHub.** The tool needs a token; it checks `$GITHUB_TOKEN` first, and if that's unset, falls back automatically to whatever the `gh` CLI is currently logged in as (`gh auth token`). Pick one:

  - **Recommended — use the `gh` CLI, no token to manage yourself:**
    ```
    gh auth login
    gh auth refresh -s repo,workflow,admin:public_key,admin:gpg_key,admin:ssh_signing_key
    ```
    Nothing further to set — the tool picks this up automatically.
  - **Or set a Personal Access Token explicitly:**
    ```
    export GITHUB_TOKEN=ghp_your_token_here
    ```
    A fine-grained or classic PAT both work. Either way it needs enough scope for what you're about to run — see the table below.

  | Scope | Needed for |
  |---|---|
  | `repo` | everything: reading repo state, creating rulesets, enabling security features |
  | `workflow` | `apply` creating/updating files under `.github/workflows/` (TruffleHog, CI) |
  | `admin:public_key`, `admin:gpg_key`, `admin:ssh_signing_key` | only if you also want to audit/register signing keys yourself (see step 4) — `apply` does not do this automatically today |

  `audit` and `plan` are read-only and work with just `repo`; add `workflow` before your first `apply` on a repo that needs a new TruffleHog or CI workflow installed.

**4. (Recommended, manual) Set up commit signing.** The controller can *require* signed commits on a repo, but it does not generate or register a signing key for you — that's a one-time step on your own workstation:
```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_signing -N ""
gh api -X POST user/ssh_signing_keys -f title="my signing key" -f key="$(cat ~/.ssh/id_ed25519_signing.pub)"
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgsign true
```
Use a *dedicated* key here, separate from any key you use for SSH authentication — see [ADR-0003](docs/adr/0003-dedicated-ssh-signing-key.md) for why that separation matters. Note: only commits made *after* the key is registered will verify; GitHub does not retroactively verify older ones.

**5. Run your first command — read-only, safe to try immediately:**
```
./github-security-controller audit --repo YOUR_OWNER/YOUR_REPO
```
This prints findings only. Nothing on GitHub changes. Try `--owner YOUR_OWNER` instead of `--repo` to audit every non-archived, non-fork repo you own at once.

**6. When you're ready to change something, plan first, then apply:**
```
./github-security-controller plan --repo YOUR_OWNER/YOUR_REPO --out plan.json
cat plan.json   # or open it in an editor — review every proposed change
./github-security-controller apply --plan plan.json
./github-security-controller verify --repo YOUR_OWNER/YOUR_REPO
```

## Command reference

```
github-security-controller audit --owner OWNER [--policy FILE] [--json]
github-security-controller audit --repo OWNER/NAME [--policy FILE]
github-security-controller plan --owner OWNER [--policy FILE] --out plan.json
github-security-controller apply --plan plan.json
github-security-controller verify --owner OWNER
github-security-controller repo create --owner OWNER --name NAME --visibility public
```

The full flow, in order: **audit → plan → review the diff yourself → apply → verify**.

1. `audit` reads live GitHub state and reports findings. Read-only, always.
2. `plan` does the same read, plus computes the exact `Change`s needed to close the gap, and writes a fingerprinted `plan.json`. Still read-only — nothing on GitHub changes yet.
3. You read `plan.json` (or its table output) and decide whether to proceed.
4. `apply --plan plan.json` re-checks live state first — if anything drifted since `plan` ran, it refuses with a staleness error rather than applying against stale assumptions (`--force` overrides this, deliberately not wired into any automated path).
5. `verify` re-audits after applying, to confirm the changes actually took effect the way you expected.

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
