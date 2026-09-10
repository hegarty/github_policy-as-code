# 9. A required status check must only be required where it will actually run

## Status
Accepted

## Context
`security-policy.yaml`'s `default_branch.required_status_check_contexts` originally passed straight through to every ruleset unconditionally: `["trufflehog", "build"]`. TruffleHog gets installed on every repo the policy targets, so that half was always safe. The `"build"` context comes from the CI workflow this engine installs — but that workflow is only generated for repos with `PrimaryLanguage == "Go"` (see the CI section of `internal/policy/evaluate.go`).

This was caught during planning for the 15-repo public rollout, before anything was applied: only 3 of the 15 targeted repos are Go. For the other 12, the generated ruleset would have required a `"build"` status check that no workflow would ever produce — GitHub's required-status-checks rule blocks merge on a required check that never reports, so every future PR on those 12 repos would have been permanently unmergeable (short of the repository-admin bypass) until someone noticed and manually fixed the ruleset.

## Decision
`internal/policy.computeRequiredStatusChecks(state, pol)` filters the policy's configured context list per repo before it reaches the ruleset:
- `"trufflehog"` is kept only if `security.trufflehog.enabled` is true.
- `"build"` is kept only if `state.PrimaryLanguage == "Go"` — the same condition that decides whether the CI-workflow-install `Change` is proposed in the first place.
- Any other context name is passed through unfiltered, on the assumption an operator who added a custom context to policy did so deliberately for a check some other system already produces (e.g. an existing non-Go CI pipeline).

## Consequences
- A ruleset on a non-Go repo currently requires only `trufflehog` as a status check, not `build`. If Go-agnostic CI workflow support is added later (tracked in `SESSION.md`'s known-gaps list), this filter needs to grow alongside it — the underlying principle (never require a check with no path to existing) applies regardless of which languages are supported.
- This is the same failure class as ADR-0007's Enterprise-only `evaluate` mode discovery and ADR-0008's silent-no-op PATCH: a plan that looked correct in isolation, caught only by checking it against real per-repo state before applying. None of the three were caught by unit tests alone — all three were caught by generating a real plan against real repos and reading it critically before hitting apply.
