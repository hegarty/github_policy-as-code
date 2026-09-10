# 4. Fingerprinted plans with staleness rejection

## Status
Accepted

## Context
`plan` and `apply` run as separate steps, potentially minutes or longer apart, with a human approval gate in between. GitHub state can change in that window (someone else edits branch protection, a collaborator is added, etc.). Applying a plan computed against stale assumptions risks either failing confusingly or, worse, succeeding in a way that silently reverts someone else's intervening change.

## Decision
`internal/plan.Plan` records a SHA-256 hash of each targeted repo's normalized `ghapi.RepoState` (`plan.RepoPlan.StateHash`) plus a hash of the policy file used, and combines them into one overall `Fingerprint`. `apply` re-collects live state for every repo in the plan immediately before applying anything, recomputes hashes, and calls `Plan.CheckFresh` — any mismatch aborts with a `StaleReposError` (exit code 3) unless `--force` is explicitly passed. `plan.Load` also independently re-verifies the fingerprint against the plan file's own contents, rejecting a hand-edited or corrupted `plan.json`.

## Consequences
- A real bug this surfaced during dogfooding: `RepoState.FetchedAt` was originally included in the hashed state, so *any* two collections of an unchanged repo produced different hashes — every fresh audit looked stale relative to any prior plan, regardless of real drift. Fixed by `RepoState.ForHashing()`, which zeroes `FetchedAt` before hashing (see `internal/ghapi/types.go` and its regression test). Any future field added to `RepoState` that reflects collection-time rather than repo-state must go through `ForHashing()` or repeat this bug.
- `apply --force` exists as an explicit escape hatch but is not wired into any automated path — it requires a human to type it.
