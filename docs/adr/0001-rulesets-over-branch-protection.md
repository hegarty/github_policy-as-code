# 1. Use GitHub rulesets, not classic branch protection

## Status
Accepted

## Context
GitHub has two mechanisms for protecting a branch: classic "branch protection rules" and the newer "rulesets" API. They overlap heavily but aren't identical — rulesets support layering (org-wide + repo-level), an `evaluate` (dry-run) enforcement mode, explicit bypass-actor lists as first-class config, and apply to both branches and tags from one API surface. Classic branch protection has none of these and is being de-emphasized by GitHub in current guidance.

## Decision
The controller manages trunk protection exclusively through the rulesets API (`POST/PUT/GET /repos/{owner}/{repo}/rulesets`), not classic branch protection. `ghapi.Client.GetBranchProtection` still exists and is read during audit, purely so drift onto classic protection (e.g. a repo that had it configured before the controller existed) is visible — the controller never writes to it.

## Consequences
- One ruleset per repo, named `main-trunk-protection`, owns force-push/deletion/signature/status-check/linear-history rules plus the bypass-actor list.
- `internal/policy.Evaluate` looks for a ruleset by that exact name; it does not currently reconcile a differently-named ruleset or a classic branch protection rule that happens to enforce equivalent controls. A repo with hand-configured classic protection will show as non-compliant even if its effective protection is adequate — see ADR-0007's related note on partial ruleset-detail auditing.
- Rulesets are billed/gated differently than branch protection on some plans — see ADR-0006 for the enforcement-mode gap this produced in practice.
