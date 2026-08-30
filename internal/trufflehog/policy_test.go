package trufflehog_test

import (
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/trufflehog"
)

func TestInspect_NotInstalled(t *testing.T) {
	s := trufflehog.Inspect(nil)
	if s.Installed {
		t.Error("expected Installed=false with no workflows")
	}
}

func TestInspect_WellFormedWorkflow(t *testing.T) {
	content := `
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
jobs:
  trufflehog:
    steps:
      - uses: trufflesecurity/trufflehog@20652fbbdefffcdaa493a5bf57ab2ac6b1db715b
        with:
          extra_args: --results=verified,unknown
`
	s := trufflehog.Inspect([]ghapi.WorkflowFile{{Path: ".github/workflows/trufflehog.yml", Content: content}})

	if !s.Installed {
		t.Fatal("expected Installed=true")
	}
	if !s.TriggersOnPROpen || !s.TriggersOnPRSync || !s.TriggersOnPRReopen {
		t.Errorf("expected all three PR triggers detected, got %+v", s)
	}
	if !s.PinnedToSHA {
		t.Error("expected PinnedToSHA=true for a 40-char hex ref")
	}
	if s.UsesMutableRef {
		t.Error("did not expect UsesMutableRef for a SHA-pinned action")
	}
	if !s.FailsOnUnverified {
		t.Error("expected FailsOnUnverified=true for --results=verified,unknown")
	}
	if !s.MinimalTokenPermissions {
		t.Error("expected MinimalTokenPermissions=true when contents: read is declared")
	}
}

func TestInspect_MutableRefAndExclusions(t *testing.T) {
	content := `
on:
  push:
    branches: [main]
jobs:
  trufflehog:
    steps:
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --results=verified --exclude-paths=foo.txt
`
	s := trufflehog.Inspect([]ghapi.WorkflowFile{{Path: ".github/workflows/trufflehog.yml", Content: content}})

	if !s.UsesMutableRef {
		t.Error("expected UsesMutableRef=true for @main")
	}
	if s.PinnedToSHA {
		t.Error("did not expect PinnedToSHA for a mutable ref")
	}
	if !s.HasExclusions {
		t.Error("expected HasExclusions=true")
	}
}

func TestEvaluate_NotInstalledIsHighAndStops(t *testing.T) {
	findings := trufflehog.Evaluate(trufflehog.State{}, false, true, true)
	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("expected exactly one HIGH finding for a missing install, got %+v", findings)
	}
}

func TestEvaluate_InstalledButNotRequired(t *testing.T) {
	s := trufflehog.State{
		Installed: true, TriggersOnPROpen: true, TriggersOnPRSync: true, TriggersOnPRReopen: true,
		PinnedToSHA: true, FailsOnVerified: true, FailsOnUnverified: true, MinimalTokenPermissions: true,
	}
	findings := trufflehog.Evaluate(s, false /* requiredCheck */, true, true)

	found := false
	for _, f := range findings {
		if f.Severity == "HIGH" {
			found = true
		}
	}
	if !found {
		t.Error("expected a HIGH finding when TruffleHog is installed but not a required status check")
	}
}

func TestEvaluate_FailOnVerifiedMissingIsCritical(t *testing.T) {
	s := trufflehog.State{
		Installed: true, TriggersOnPROpen: true, TriggersOnPRSync: true, TriggersOnPRReopen: true,
		PinnedToSHA: true, FailsOnVerified: false, MinimalTokenPermissions: true,
	}
	findings := trufflehog.Evaluate(s, true, true /* policy requires fail_on_verified */, false)

	criticalFound := false
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			criticalFound = true
		}
	}
	if !criticalFound {
		t.Error("expected a CRITICAL finding when policy requires failing on verified secrets but the workflow doesn't")
	}
}
