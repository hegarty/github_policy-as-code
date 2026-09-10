# 10. Generated CI workflow reads its Go version from the target repo, not a hardcoded default

## Status
Accepted

## Context
`internal/workflows.RenderCI` originally hardcoded `go-version: "1.22"` into the `actions/setup-go` step of every CI workflow it installs — a fixed default (from a `--go-version` CLI flag, itself defaulted to `"1.22"`), unrelated to what any specific target repo's own `go.mod` actually requires.

This broke real PRs after the 15-repo rollout: `bedrock-proxy`'s `go.mod` declares `go 1.24`. Its installed CI workflow requested Go 1.22 via `setup-go`, and with `GOTOOLCHAIN=local` (the runner's default), the build step failed immediately: `go: go.mod requires go >= 1.24 (running go 1.22.12; GOTOOLCHAIN=local)`. Every future PR on that repo would have failed the required `build` check for the same reason, indefinitely, until someone noticed and manually edited the installed workflow.

## Decision
`RenderCI` no longer takes a Go version parameter at all. The rendered workflow uses `actions/setup-go`'s `go-version-file: go.mod` input, which reads the exact version constraint from the target repo's own `go.mod` at workflow run time — always in sync with what that repo actually declares, by construction, with nothing for policy or the CLI to keep updated.

## Consequences
- `CIParams.GoVersion`, the `plan --go-version` flag, and the `go_version` `Change.Params` key are all removed — there was nothing correct to put in them.
- This fixes repos with a single `go.mod` at the repository root. It does **not** fix repos with a different structure:
  - **Multi-module repos** (e.g. `edge-monitor-app`: five separate `go.mod` files in subdirectories, no root module) — `go-version-file: go.mod` and `go build ./...` both still assume one module at the repo root. `setup-go` now fails clearly at the "Set up Go" step (`go.mod` not found) rather than the confusing toolchain-mismatch error further into the build, but the underlying gap — no multi-module support in the generated CI workflow — is real and untouched by this fix.
  - **Repos with no `go.mod` at all** despite having `.go` source files and a GitHub-detected primary language of Go (e.g. `terragrunt-ops`, which has a root `main.go` but no `go.mod` anywhere) — this is a pre-existing state of the repo's own content, not something any CI template can route around. The controller installed a policy-correct CI workflow for a repo GitHub itself classifies as Go; the repo isn't actually buildable as a Go module yet. That's the repo owner's call to fix (add a `go.mod`) or to exclude from the CI-workflow expectation, not the controller's to silently paper over.
- Neither of those two remaining gaps is fixed by this ADR. Tracked in `SESSION.md`'s known-gaps list as follow-up work: multi-module detection (walk for `go.mod` files, generate a matrix build) and a pre-flight "does this repo actually have a buildable Go module" check before proposing the CI-workflow `Change` at all.
