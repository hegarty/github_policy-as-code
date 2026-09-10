# 6. Required-review count adapts to collaborator count

## Status
Accepted

## Context
Requiring 1 approving review on a single-maintainer repo creates an impossible self-approval trap: the only collaborator can never merge their own PR. A blanket "require 1 review" policy is wrong for the common case in this account (every repo audited this session had exactly one collaborator).

## Decision
`ghapi.RepoState.SoloMaintainer()` reports true when a repo has one or fewer direct collaborators. `internal/policy.Evaluate` selects `security-policy.yaml`'s `default_branch.required_approving_review_count.solo_maintainer` (0) or `.multi_maintainer` (1) accordingly, per repo, automatically — no manual per-repo override needed. The solo-maintainer model relies on PR + signed commits + required status checks as the control set, without a review-count requirement.

## Consequences
- Adding a second collaborator to a repo automatically tightens its required review count on the next `plan`/`apply` — no separate policy change needed.
- The reverse isn't automatic in the other direction on its own: removing a collaborator down to solo doesn't retroactively loosen an already-active ruleset until `apply` runs again. This is intentional — loosening a control should still go through the same plan/apply/approval flow as tightening one, not happen silently.
