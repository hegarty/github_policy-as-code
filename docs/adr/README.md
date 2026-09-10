# Architecture Decision Records

Numbered, append-only. Each record captures a decision, the context that drove it, and its known consequences — including gaps discovered while dogfooding, not just the happy path. Superseding a decision means adding a new ADR that says so, not editing the old one.

| # | Decision |
|---|---|
| [0001](0001-rulesets-over-branch-protection.md) | Use GitHub rulesets, not classic branch protection |
| [0002](0002-hand-rolled-rest-client.md) | Hand-rolled REST client instead of google/go-github |
| [0003](0003-dedicated-ssh-signing-key.md) | Dedicated SSH signing key, separate from the authentication key |
| [0004](0004-fingerprinted-plans.md) | Fingerprinted plans with staleness rejection |
| [0005](0005-trufflehog-as-policy-control.md) | TruffleHog audited as a policy control, not just a file's existence |
| [0006](0006-solo-vs-multi-maintainer-reviews.md) | Required-review count adapts to collaborator count |
| [0007](0007-enforcement-mode-plan-gap.md) | Ruleset `evaluate` enforcement requires GitHub Enterprise — active-only fallback |
| [0008](0008-conservative-paid-feature-defaults.md) | Never auto-enable paid security features on private repos |
| [0009](0009-required-checks-must-be-reachable.md) | A required status check must only be required where it will actually run |
