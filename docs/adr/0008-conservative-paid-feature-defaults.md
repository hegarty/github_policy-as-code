# 8. Never auto-enable paid security features on private repos

## Status
Accepted

## Context
GitHub Advanced Security was unbundled into standalone paid products (Secret Protection, Code Security) effective April 2025. Secret scanning, push protection, and CodeQL default setup are free only on **public** repositories; enabling them on a private repo can incur per-committer billing the account owner didn't explicitly opt into.

## Decision
`security.codeql.private_repos` defaults to `false` in `security-policy.yaml`. `internal/policy.Evaluate`'s CodeQL section only proposes an `enable_codeql_default_setup` change when the repo is public, or when `private_repos: true` is explicitly set. For a private, CodeQL-eligible repo with the flag off, the engine emits an `INFO`-severity finding explaining why it wasn't auto-enabled, rather than silently skipping it or silently enabling it.

The same conservative-default principle applies to secret scanning and push protection changes, gated on `state.Visibility == "public"` before any `Change` is proposed.

## Consequences
- Bringing the 17 private repos in this account into scope (not yet done) will surface a batch of these `INFO` findings rather than a batch of surprise-billing `Change`s. That's intended — the operator has to make an explicit, informed opt-in decision per repo or policy-wide, not discover a bill.
- `security_and_analysis` PATCH calls were observed to sometimes return `HTTP 200` while silently not changing the underlying setting (`secret_scanning_validity_checks` specifically, confirmed on this account's plan tier — see `internal/ghapi/client.go`'s doc comment on `SetSecretScanningValidityChecks`). This is a different failure mode than the plan-tier `422` in ADR-0007: no error at all, just a no-op. `apply` currently treats the HTTP-level success as success; it does not verify the resulting state actually changed. Known gap, not yet fixed.
