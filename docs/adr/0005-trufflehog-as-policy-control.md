# 5. TruffleHog audited as a policy control, not just a file's existence

## Status
Accepted

## Context
It's easy for a "require TruffleHog" policy to degrade into "a file named trufflehog.yml exists" — which doesn't catch a scanner that's been weakened (mutable Action ref, missing PR triggers, exclusions added, no longer required as a status check) without anyone touching the ruleset itself. The threat model explicitly calls out bypass-by-configuration as a risk category.

## Decision
`internal/trufflehog.Inspect` parses the installed workflow's actual content (not just its presence) into a `State` struct: which PR events it triggers on, whether the Action reference is a pinned SHA vs. a mutable branch/tag, whether exclusions are present, whether it fails on verified/unverified secrets, whether it declares minimal token permissions. `internal/trufflehog.Evaluate` compares that state against policy intent and produces graded findings (a missing install is `HIGH`; not failing on verified secrets when policy requires it is `CRITICAL`).

A same-repo separate workflow — the one-time full-history onboarding scan (`trufflehog-full-history.yml`, `workflow_dispatch`-only) — also references `trufflesecurity/trufflehog` and must not be mistaken for the PR-gating scan. `Inspect` selects by the canonical path (`.github/workflows/trufflehog.yml`) first, falling back to "does it trigger on `pull_request`" only if that exact path isn't found.

## Consequences
- A real bug this design surfaced during dogfooding: before the path-based selection existed, `Inspect` picked whichever workflow file happened to sort first alphabetically when scanning for `trufflesecurity/trufflehog`, which put the full-history scan ahead of the real one and produced a false "does not trigger on PR events" finding. Fixed; regression covered implicitly by the existing evaluate tests continuing to pass against the two-workflow fixture set, and explicitly by `internal/trufflehog/policy_test.go`.
- `Evaluate` currently has a known gap: when TruffleHog is present but weakened (not missing), the engine produces findings but does **not** propose a targeted "fix" `Change` — only a missing install gets a remediation `Change`. A weakened-but-present TruffleHog requires a human to read the finding and manually correct the workflow file; see `TestEvaluate_WeakenedTruffleHog`'s comment for the explicit acknowledgment of this v1 scope limit.
