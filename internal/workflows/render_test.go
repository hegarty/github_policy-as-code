package workflows_test

import (
	"strings"
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/workflows"
)

func TestRenderTruffleHog_PinsSHAsAndTriggers(t *testing.T) {
	out := workflows.RenderTruffleHog(workflows.TruffleHogParams{
		CheckoutSHA:      "1111111111111111111111111111111111111111",
		TruffleHogSHA:    "2222222222222222222222222222222222222222",
		FailOnUnverified: true,
		DefaultBranch:    "main",
	})

	for _, want := range []string{
		"actions/checkout@1111111111111111111111111111111111111111",
		"trufflesecurity/trufflehog@2222222222222222222222222222222222222222",
		"types: [opened, synchronize, reopened]",
		"contents: read",
		"--results=verified,unknown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered workflow missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTruffleHog_FailOnVerifiedOnly(t *testing.T) {
	out := workflows.RenderTruffleHog(workflows.TruffleHogParams{
		CheckoutSHA:      "1111111111111111111111111111111111111111",
		TruffleHogSHA:    "2222222222222222222222222222222222222222",
		FailOnUnverified: false,
		DefaultBranch:    "main",
	})
	if strings.Contains(out, "--results=verified,unknown") {
		t.Error("expected --results=verified only when FailOnUnverified is false")
	}
	if !strings.Contains(out, "--results=verified") {
		t.Error("expected --results=verified to always be present")
	}
}

func TestRenderCI_PinsSHAsAndGoVersion(t *testing.T) {
	out := workflows.RenderCI(workflows.CIParams{
		CheckoutSHA:   "1111111111111111111111111111111111111111",
		SetupGoSHA:    "3333333333333333333333333333333333333333",
		GoVersion:     "1.22",
		DefaultBranch: "main",
	})
	for _, want := range []string{
		"actions/checkout@1111111111111111111111111111111111111111",
		"actions/setup-go@3333333333333333333333333333333333333333",
		`go-version: "1.22"`,
		"go build ./...",
		"go vet ./...",
		"go test ./...",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered CI workflow missing %q:\n%s", want, out)
		}
	}
}
