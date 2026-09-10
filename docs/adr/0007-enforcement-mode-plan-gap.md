# 7. Ruleset `evaluate` enforcement requires GitHub Enterprise — active-only fallback

## Status
Accepted (with a known, documented gap)

## Context
The original design staged every new ruleset in GitHub's `evaluate` (dry-run/report-only) enforcement mode first, promoting to `active` only after a verify cycle confirmed no unexpected blocks — a deliberately cautious rollout for a control that can lock out contributors if misconfigured.

Applying that policy against this account's real plan tier failed:

```
POST /repos/hegarty/github_policy-as-code/rulesets -> HTTP 422
"Enforcement evaluate option is not supported on this plan.
 Please upgrade to Enterprise to enable it."
```

This is not documented as an explicit plan restriction in GitHub's public docs as of this writing — it was discovered via the live API response, not anticipated in advance.

## Decision
For `github_policy-as-code` specifically, given it was a brand-new repo with zero PR history to disrupt and the repository-admin bypass actor retained as a safety net, the human operator approved going straight to `active` enforcement rather than attempting `evaluate` first. `security-policy.yaml` still declares `enforcement: evaluate` as the aspirational default (correct for GitHub Enterprise accounts, and this tool must stay plan-agnostic since it's meant to work across arbitrary owners), with an inline comment documenting the Free/Pro/Team-tier failure and noting that callers must override to `active` for those accounts.

## Consequences
- **The controller does not yet auto-detect this capability gap.** It was diagnosed and worked around manually, per-invocation, by generating the plan against a policy file with `enforcement: active` instead of the checked-in default. There is no code path today that catches the 422, classifies it as a plan-tier limitation, and falls back automatically — this is a real gap relative to the project's own stated goal ("detect capabilities and report unsupported controls"), tracked as follow-up work, not yet built.
- Any future repo rollout (the 15-repo backlog, or a new org) needs the same manual override until that auto-detection lands. Don't assume `evaluate` will work without checking the account's plan first.
- Rolling out to a repo *with* existing PR/contributor activity should not casually reuse this "go straight to active" precedent — that decision was specifically justified by zero existing history on this one repo. Re-evaluate case-by-case.
