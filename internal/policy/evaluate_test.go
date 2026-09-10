package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/config"
	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/policy"
)

func loadFixture(t *testing.T, name string) *ghapi.RepoState {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var state ghapi.RepoState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return &state
}

func hasControl(findings []policy.Finding, control string) bool {
	for _, f := range findings {
		if f.Control == control {
			return true
		}
	}
	return false
}

func maxSeverity(findings []policy.Finding) policy.Severity {
	rank := map[policy.Severity]int{
		policy.SeverityInfo: 0, policy.SeverityLow: 1, policy.SeverityMedium: 2,
		policy.SeverityHigh: 3, policy.SeverityCritical: 4,
	}
	best := policy.SeverityInfo
	for _, f := range findings {
		if rank[f.Severity] > rank[best] {
			best = f.Severity
		}
	}
	return best
}

func TestEvaluate_Compliant(t *testing.T) {
	state := loadFixture(t, "compliant")
	// The compliant fixture represents the fully rolled-out end state
	// (ruleset already promoted to active enforcement), so evaluate it
	// against a policy that has likewise been promoted — the built-in
	// Default() intentionally starts every repo in "evaluate" mode for
	// staged rollout, which is a different (also valid) state.
	pol := config.Default()
	pol.DefaultBranch.Enforcement = "active"

	findings, changes := policy.Evaluate(state, pol)

	if len(changes) != 0 {
		t.Errorf("expected no changes for a fully compliant repo, got %d: %+v", len(changes), changes)
	}
	for _, f := range findings {
		if f.Severity == policy.SeverityHigh || f.Severity == policy.SeverityCritical {
			t.Errorf("unexpected high-severity finding on compliant fixture: %+v", f)
		}
	}
}

func TestEvaluate_Insecure(t *testing.T) {
	state := loadFixture(t, "insecure")
	pol := config.Default()

	findings, changes := policy.Evaluate(state, pol)

	if !hasControl(findings, "ruleset") {
		t.Error("expected a ruleset finding for a repo with no ruleset")
	}
	if !hasControl(findings, "trufflehog") {
		t.Error("expected a trufflehog finding for a repo with no TruffleHog workflow")
	}
	if !hasControl(findings, "actions_token_permissions") {
		t.Error("expected an actions_token_permissions finding for write-by-default token")
	}
	if maxSeverity(findings) != policy.SeverityHigh && maxSeverity(findings) != policy.SeverityCritical {
		t.Errorf("expected at least a HIGH finding for a fully insecure repo, got max severity %s", maxSeverity(findings))
	}
	if len(changes) == 0 {
		t.Error("expected proposed changes for an insecure repo")
	}
}

func TestEvaluate_SoloMaintainer_ZeroRequiredReviews(t *testing.T) {
	state := loadFixture(t, "solo-maintainer")
	pol := config.Default()

	_, changes := policy.Evaluate(state, pol)

	for _, c := range changes {
		if c.Control != "ruleset" {
			continue
		}
		reviews, _ := c.Params["required_approving_reviews"].(int)
		if reviews != 0 {
			t.Errorf("solo maintainer should get 0 required approving reviews, got %d", reviews)
		}
	}
}

func TestEvaluate_MultiMaintainer_RequiresReview(t *testing.T) {
	state := loadFixture(t, "multi-maintainer")
	pol := config.Default()

	if state.SoloMaintainer() {
		t.Fatal("fixture setup error: multi-maintainer fixture should not be solo")
	}

	// No ruleset exists yet, so Evaluate must propose creating one — with
	// the multi-maintainer (not solo) required review count.
	state.Rulesets = nil
	_, changes := policy.Evaluate(state, pol)

	found := false
	for _, c := range changes {
		if c.Control == "ruleset" {
			found = true
			reviews, _ := c.Params["required_approving_reviews"].(int)
			if reviews != 1 {
				t.Errorf("multi maintainer should get 1 required approving review, got %d", reviews)
			}
		}
	}
	if !found {
		t.Fatal("expected a ruleset change when no ruleset exists")
	}
}

func TestEvaluate_NoMain_ReportsOnlyNoChanges(t *testing.T) {
	state := loadFixture(t, "no-main")
	pol := config.Default()

	findings, changes := policy.Evaluate(state, pol)

	if len(changes) != 0 {
		t.Errorf("an empty repo should produce no changes (nothing to target yet), got %d", len(changes))
	}
	if !hasControl(findings, "trunk") {
		t.Error("expected a trunk finding noting the repo has no commits")
	}
	for _, f := range findings {
		if f.Control == "trunk" && f.Severity != policy.SeverityInfo {
			t.Errorf("empty-repo finding should be INFO, got %s", f.Severity)
		}
	}
}

func TestEvaluate_Production_PrivateCodeQLNotAutoEnabled(t *testing.T) {
	state := loadFixture(t, "production")
	pol := config.Default() // private_repos defaults to false

	findings, changes := policy.Evaluate(state, pol)

	for _, c := range changes {
		if c.Kind == policy.KindEnableCodeQL {
			t.Errorf("CodeQL must not be auto-enabled on a private repo when security.codeql.private_repos is false, got change: %+v", c)
		}
	}
	if !hasControl(findings, "codeql") {
		t.Error("expected an informational finding explaining why CodeQL was not auto-enabled on this private, eligible repo")
	}
}

func TestEvaluate_UnsafeWorkflow_FlagsMissingTruffleHogAndPermissions(t *testing.T) {
	state := loadFixture(t, "unsafe-workflow")
	pol := config.Default()

	findings, _ := policy.Evaluate(state, pol)

	if !hasControl(findings, "trufflehog") {
		t.Error("expected a trufflehog finding — the only workflow present is an unrelated, unsafe CI workflow")
	}
	if !hasControl(findings, "actions_token_permissions") {
		t.Error("expected a finding for the write-by-default token permissions")
	}
}

func TestEvaluate_MissingTruffleHog(t *testing.T) {
	state := loadFixture(t, "missing-trufflehog")
	pol := config.Default()

	findings, changes := policy.Evaluate(state, pol)

	if !hasControl(findings, "trufflehog") {
		t.Fatal("expected a trufflehog finding")
	}
	installFound := false
	for _, c := range changes {
		if c.Kind == policy.KindInstallTruffleHogWorkflow {
			installFound = true
		}
	}
	if !installFound {
		t.Error("expected an install_trufflehog_workflow change")
	}
}

func TestEvaluate_WeakenedTruffleHog(t *testing.T) {
	state := loadFixture(t, "weakened-trufflehog")
	pol := config.Default()

	findings, changes := policy.Evaluate(state, pol)

	var thFindings []policy.Finding
	for _, f := range findings {
		if f.Control == "trufflehog" {
			thFindings = append(thFindings, f)
		}
	}
	if len(thFindings) < 3 {
		t.Errorf("expected multiple trufflehog weakening findings (mutable ref, missing triggers, exclusions, unverified-not-failed), got %d: %+v", len(thFindings), thFindings)
	}
	// A weakened-but-present TruffleHog should not trigger a fresh install
	// change — that would be the wrong remediation. This is a known v1 gap:
	// the engine doesn't yet propose a targeted "fix" change for a degraded
	// install, only for a missing one.
	for _, c := range changes {
		if c.Kind == policy.KindInstallTruffleHogWorkflow {
			t.Error("did not expect a fresh install change when TruffleHog is present but weakened")
		}
	}
}

func TestEvaluate_BypassActorDrift(t *testing.T) {
	state := loadFixture(t, "bypass-actor-drift")
	pol := config.Default()

	findings, _ := policy.Evaluate(state, pol)

	var driftFindings []policy.Finding
	for _, f := range findings {
		if f.Control == "bypass_actors" {
			driftFindings = append(driftFindings, f)
		}
	}
	if len(driftFindings) != 1 {
		t.Fatalf("expected exactly one unapproved-bypass-actor finding, got %d: %+v", len(driftFindings), driftFindings)
	}
	if driftFindings[0].Severity != policy.SeverityCritical {
		t.Errorf("unapproved bypass actor should be CRITICAL, got %s", driftFindings[0].Severity)
	}
}

func TestEvaluate_CodeQLLanguageIDIsAPICompatible(t *testing.T) {
	// Regression test: GitHub's code-scanning default-setup API rejects the
	// Linguist-style "Go" (confirmed via a live 422) and wants lowercase
	// "go" instead. Evaluate must translate, not pass RepoState.PrimaryLanguage
	// straight through.
	state := loadFixture(t, "solo-maintainer") // public, Go, code_scanning_configured: false
	pol := config.Default()

	_, changes := policy.Evaluate(state, pol)

	found := false
	for _, c := range changes {
		if c.Kind != policy.KindEnableCodeQL {
			continue
		}
		found = true
		lang, _ := c.Params["language"].(string)
		if lang != "go" {
			t.Errorf("expected CodeQL language param %q, got %q", "go", lang)
		}
	}
	if !found {
		t.Fatal("expected a CodeQL enable change for this public, Go, eligible fixture")
	}
}

func TestEvaluate_NonGoRepoDoesNotRequireBuildCheck(t *testing.T) {
	// Regression test for a real pre-rollout bug: the ruleset unconditionally
	// required a "build" status check even on repos where no CI workflow
	// would ever be installed (this engine only installs one for Go repos
	// today). That would have permanently blocked every future PR on any
	// non-Go repo, waiting on a check that never reports.
	state := loadFixture(t, "insecure") // primary_language: Shell, no ruleset yet
	if state.PrimaryLanguage == "Go" {
		t.Fatal("fixture setup error: this test needs a non-Go fixture")
	}
	pol := config.Default()

	_, changes := policy.Evaluate(state, pol)

	found := false
	for _, c := range changes {
		if c.Kind != policy.KindCreateOrUpdateRuleset {
			continue
		}
		found = true
		checks, _ := c.Params["required_status_checks"].([]string)
		for _, ctx := range checks {
			if ctx == "build" {
				t.Errorf("non-Go repo must not require a %q status check — no CI workflow will ever produce it, got required checks: %v", "build", checks)
			}
		}
		hasTrufflehog := false
		for _, ctx := range checks {
			if ctx == "trufflehog" {
				hasTrufflehog = true
			}
		}
		if !hasTrufflehog {
			t.Errorf("expected \"trufflehog\" to still be required (TruffleHog is being installed this same pass), got: %v", checks)
		}
	}
	if !found {
		t.Fatal("expected a ruleset change")
	}
}

func TestEvaluate_GoRepoDoesRequireBuildCheck(t *testing.T) {
	state := loadFixture(t, "solo-maintainer") // primary_language: Go
	if state.PrimaryLanguage != "Go" {
		t.Fatal("fixture setup error: this test needs a Go fixture")
	}
	state.Rulesets = nil // force a ruleset-create change rather than a no-op
	pol := config.Default()

	_, changes := policy.Evaluate(state, pol)

	found := false
	for _, c := range changes {
		if c.Kind != policy.KindCreateOrUpdateRuleset {
			continue
		}
		found = true
		checks, _ := c.Params["required_status_checks"].([]string)
		hasBuild := false
		for _, ctx := range checks {
			if ctx == "build" {
				hasBuild = true
			}
		}
		if !hasBuild {
			t.Errorf("Go repo should require a %q status check since a CI workflow producing it is being installed, got: %v", "build", checks)
		}
	}
	if !found {
		t.Fatal("expected a ruleset change")
	}
}

func TestEvaluate_Idempotent(t *testing.T) {
	// Running Evaluate twice against the same state must produce the same
	// findings and changes — the engine is pure and must not carry any
	// hidden mutable state between calls.
	state := loadFixture(t, "insecure")
	pol := config.Default()

	f1, c1 := policy.Evaluate(state, pol)
	f2, c2 := policy.Evaluate(state, pol)

	if len(f1) != len(f2) || len(c1) != len(c2) {
		t.Fatalf("Evaluate is not idempotent: run1=(%d findings, %d changes) run2=(%d findings, %d changes)", len(f1), len(c1), len(f2), len(c2))
	}
}
