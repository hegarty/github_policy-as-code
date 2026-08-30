// Package workflows renders the GitHub Actions workflow files the
// controller installs. Third-party and first-party actions alike are pinned
// to immutable commit SHAs, resolved by the caller and passed in — this
// package never resolves SHAs itself so rendering stays a pure, testable
// function.
package workflows

import "fmt"

// TruffleHogParams configures the rendered TruffleHog workflow.
type TruffleHogParams struct {
	CheckoutSHA      string
	TruffleHogSHA    string
	FailOnUnverified bool
	DefaultBranch    string
}

func RenderTruffleHog(p TruffleHogParams) string {
	results := "verified"
	if p.FailOnUnverified {
		results = "verified,unknown"
	}
	return fmt.Sprintf(`name: TruffleHog Secret Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [%s]

permissions:
  contents: read

jobs:
  trufflehog:
    name: trufflehog
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@%s
        with:
          fetch-depth: 0

      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@%s
        with:
          extra_args: --results=%s
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`, p.DefaultBranch, p.CheckoutSHA, p.TruffleHogSHA, results)
}

// TruffleHogFullHistoryParams configures the one-time onboarding scan.
type TruffleHogFullHistoryParams struct {
	CheckoutSHA   string
	TruffleHogSHA string
}

// RenderTruffleHogFullHistory renders a manually-dispatched workflow used
// once during onboarding to scan a repository's entire history, rather than
// the diff-only scan used on every PR thereafter.
func RenderTruffleHogFullHistory(p TruffleHogFullHistoryParams) string {
	return fmt.Sprintf(`name: TruffleHog Full History Scan (onboarding)

on:
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  trufflehog-full-history:
    name: trufflehog-full-history
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@%s
        with:
          fetch-depth: 0

      - name: TruffleHog OSS (full history)
        uses: trufflesecurity/trufflehog@%s
        with:
          extra_args: --results=verified,unknown
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`, p.CheckoutSHA, p.TruffleHogSHA)
}

// CIParams configures the rendered Go build/test workflow.
type CIParams struct {
	CheckoutSHA   string
	SetupGoSHA    string
	GoVersion     string
	DefaultBranch string
}

func RenderCI(p CIParams) string {
	return fmt.Sprintf(`name: ci

on:
  pull_request:
    branches: [%s]
  push:
    branches: [%s]

permissions:
  contents: read

jobs:
  build:
    name: build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@%s

      - name: Set up Go
        uses: actions/setup-go@%s
        with:
          go-version: %q

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test ./...
`, p.DefaultBranch, p.DefaultBranch, p.CheckoutSHA, p.SetupGoSHA, p.GoVersion)
}
