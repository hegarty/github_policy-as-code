# SESSION.md — running context for Claude

Read this first if picking up this project cold (new terminal session, context loss, or a different Claude session/agent). It's a living document — update it at the end of any session that changes the project's state or roadmap. It is **public** (this repo is public): keep it to this tool's own architecture and operating status, never to specific findings about other repositories' security posture.

## What this project is

A policy-as-code GitHub security controller (`github-security-controller`, module `github.com/hegarty/github_policy-as-code`). It establishes and continuously verifies a trusted software supply chain: developer workstation → SSH-authenticated, signed-commit GitHub access → protected trunk → CI/security checks (TruffleHog, CodeQL, tests) → protected `main`. It is explicitly **owner-agnostic** — built to work against any personal account, org, single repo, or full repo set, never hardcoding a specific account, even though the account it's being developed and proven against is `hegarty`.

Full design rationale: [`docs/adr/`](docs/adr/README.md). Usage: [`README.md`](README.md).

## Operating model (do not skip this)

This project is run under a strict phase discipline, established at the start of the engagement and still in force:

```
DISCOVER (read-only) → ASSESS → ASK ALL QUESTIONS TOGETHER → GENERATE FINAL PLAN
→ SINGLE APPROVAL GATE → EXECUTE → VERIFY → REPORT
```

- `audit` and `plan` are **strictly read-only**. Only `apply` mutates GitHub, and only for exactly the changes recorded in a plan file, after human approval.
- Never weaken an existing security control without explicit approval.
- Never auto-delete rulesets, branch protections, environments, secrets, deploy keys, webhooks, GitHub Apps, collaborators, workflows, or credentials.
- Never rewrite already-published Git history (e.g. commits already on `main`) without a separate, explicit approval — even to "fix" something cosmetic like an unverified signature.
- Credential/permission scope broadening always requires explicit approval before it happens, not after.
- All mutations must be idempotent — re-running `apply` against an already-converged repo is a no-op.

## Current state (as of this file's last update)

- **This repo (`github_policy-as-code`) is the pilot.** `main` is protected by an active ruleset: PR required, GitHub-verified signed commits required, force-push and deletion blocked, linear history required, conversation resolution required, required status checks (`build`, `trufflehog`), 0 required approving reviews (solo maintainer — see ADR-0006), bypass limited to the repository-admin role.
- TruffleHog (diff-mode + a separate one-time full-history onboarding workflow), CI (`go build`/`vet`/`test`), CodeQL default setup (language: go), Dependabot (`gomod` + `github-actions`, weekly), vulnerability alerts, and automated security fixes are all live and passing on this repo.
- The Go CLI (`audit`, `plan`, `apply`, `verify`, `repo create`) is implemented and has been exercised end-to-end against live GitHub state, not just against test fixtures.
- Rollout to the account's other public repos is **in progress** (see Roadmap item 1). Their specific findings are intentionally not enumerated here or in any file checked into this public repo; see the project owner directly for that status if you're a future Claude session that needs it, or regenerate it with `audit`/`plan`. Private repos remain untouched — not yet in scope.
- Phase 2 (AWS Lambda + EventBridge scheduled audit) has not been started — deliberately deferred until the CLI is proven out further.

## Known gaps (real, not hypothetical — tracked, not yet fixed)

1. **No automatic plan-tier capability detection.** Ruleset `evaluate` enforcement mode requires GitHub Enterprise; this was discovered via a live `422`, not detected in advance. See ADR-0007. Any new rollout needs a manual enforcement-mode check first.
2. **`apply` doesn't verify post-conditions for all mutations.** At least one GitHub API call (`secret_scanning_validity_checks`) returns `HTTP 200` while silently not changing the setting. `apply` currently reports this as success. See ADR-0008.
3. **TruffleHog weakened-but-present doesn't get a remediation `Change`**, only a `Finding` — only a *missing* install gets an automatic fix proposed. See ADR-0005.
4. **Ruleset drift detection is shallow.** `policy.Evaluate` checks a named ruleset's existence and top-level `enforcement` field, and separately checks bypass actors, but doesn't deeply reconcile every individual rule parameter (e.g. exact required-status-check list contents) against policy on every audit pass.
5. **No pagination beyond one page (100) when listing an owner's repos.** Not yet hit in practice (largest account audited so far: 37 repos), but will silently under-count on a larger owner.
6. **The generated CI workflow assumes a single `go.mod` at the repo root.** No multi-module support (a repo with several `go.mod` files in subdirectories, like `edge-monitor-app`, gets a CI workflow that can't find a module to build) and no pre-flight check for "does this repo actually have a `go.mod` at all" before proposing the CI-workflow change (a repo GitHub classifies as Go but that has no `go.mod` anywhere, like `terragrunt-ops`, still gets a workflow that can never pass). See ADR-0010.

**Recently resolved:**
- Planning the public-repo rollout surfaced a real pre-execution bug — the ruleset unconditionally required a `"build"` status check even on repos where no CI workflow would ever produce one, which would have permanently blocked every future PR on every non-Go repo. Caught by reading a generated plan critically before applying, not by a unit test. Fixed in `internal/policy.computeRequiredStatusChecks` — see [ADR-0009](docs/adr/0009-required-checks-must-be-reachable.md).
- After the rollout, real PRs on `bedrock-proxy` started failing CI with a Go toolchain version mismatch — the generated workflow hardcoded `go-version: "1.22"` regardless of what each repo's own `go.mod` actually required. Fixed by switching to `go-version-file: go.mod` so the workflow always matches the repo it's installed in — see [ADR-0010](docs/adr/0010-ci-workflow-reads-go-version-from-repo.md). Surfaced gap #6 above in the process.

## Credential / environment notes

- Local `gh` CLI session (account `hegarty`) holds these OAuth scopes as of the last session: `admin:gpg_key`, `admin:public_key`, `admin:ssh_signing_key`, `gist`, `read:org`, `repo`, `workflow`. No `admin:org` (no org currently in scope), no `delete_repo`.
- The controller resolves its GitHub token from `$GITHUB_TOKEN` if set, else falls back to `gh auth token`.
- A dedicated SSH signing key exists at `~/.ssh/id_ed25519_signing` (registered on GitHub as a *signing* key, distinct from the authentication key) — see ADR-0003. Global git config (`gpg.format=ssh`, `user.signingkey`, `commit.gpgsign=true`) is already set on the workstation this was developed on; a fresh environment would need this redone.
- The bootstrap commit on `main` (`5a8279a`) predates signing-key registration and will always show "Unverified" — this is expected and was a deliberate decision, not a bug to chase.

## Roadmap / next steps

1. **In progress:** rolling the same baseline out to the rest of the account's public repos (same `plan` → review → `apply` flow already proven on this repo).
2. Decide whether/how to bring private repos into scope — several are infrastructure-heavy (Terraform/AWS-adjacent) and were flagged as higher priority in the original threat model, but CodeQL/secret-scanning are paid features on private repos, so this needs an explicit policy decision first (see ADR-0008).
3. Close the known gaps above, roughly in order of security impact: (1) plan-tier capability auto-detection, (2) post-condition verification on mutations, (3) ruleset deep-diff, (4) weakened-TruffleHog remediation, (5) pagination.
4. Phase 2: AWS Lambda + EventBridge scheduled audit-only execution, using a narrowly-scoped GitHub App rather than a long-lived personal token.

## Where to look for more

- `security-policy.yaml` — the actual policy schema and current defaults, with inline comments on known plan-tier gotchas.
- `docs/adr/` — why things are built the way they are, including the real bugs and platform surprises that shaped each decision.
- `internal/policy/evaluate_test.go` and `testdata/fixtures/` — the clearest concrete description of what "compliant" vs. each failure mode actually looks like, in code.
