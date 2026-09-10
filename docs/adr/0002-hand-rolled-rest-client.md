# 2. Hand-rolled REST client instead of google/go-github

## Status
Accepted

## Context
`internal/ghapi` needs to call a fairly small, fixed set of GitHub REST endpoints (repo metadata, rulesets, Actions permissions, contents, code scanning, security-and-analysis, SSH signing keys). `google/go-github` is the standard, well-maintained typed client, but at the version evaluated it pulled in a `golang.org/x/oauth2` requirement that in turn forced the module's `go` directive up to 1.25, ahead of what's installed in the working environment (1.21/1.22 via asdf), and some of the newer endpoints used here (rulesets, code-scanning default-setup) either weren't present or their exact method signatures weren't confidently known without deeper verification.

## Decision
`internal/ghapi.Client` is implemented directly against `net/http` and `encoding/json`, authenticated with a bearer token (`Authorization: Bearer ...`) and `X-GitHub-Api-Version: 2022-11-28`. Every method is a thin, explicit REST call with typed request/response structs local to this package. `Client` is defined as an interface specifically so `internal/apply`'s tests can supply an in-memory mock without touching the network — see `internal/apply/apply_test.go`.

## Consequences
- Zero third-party runtime dependency beyond `gopkg.in/yaml.v3` (for policy parsing) — a deliberately small supply-chain surface for a security tool.
- The controller owns pagination, retries, and error shaping itself. Currently: no retry logic, no pagination beyond a single page (`per_page=100`) for repo listing. An owner with more than 100 repos will only see the first page — a known gap, not yet hit in practice (largest owner audited this session: 37 repos).
- Every new GitHub endpoint the controller needs requires hand-writing a struct and a method, rather than getting one for free from an upstream client. Acceptable at the current surface area; revisit if the endpoint count grows substantially.
