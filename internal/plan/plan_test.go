package plan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/plan"
	"github.com/hegarty/github_policy-as-code/internal/policy"
)

func sampleRepoPlans() []plan.RepoPlan {
	return []plan.RepoPlan{
		{
			Owner: "hegarty", Repo: "repo-a", StateHash: "hash-a",
			Findings: []policy.Finding{{Repo: "hegarty/repo-a", Control: "ruleset", Severity: policy.SeverityHigh, Message: "missing"}},
			Changes:  []policy.Change{{Repo: "hegarty/repo-a", Control: "ruleset", Kind: policy.KindCreateOrUpdateRuleset}},
		},
		{Owner: "hegarty", Repo: "repo-b", StateHash: "hash-b"},
	}
}

func TestPlan_FingerprintDeterministic(t *testing.T) {
	p1 := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())
	p2 := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())

	if p1.Fingerprint != p2.Fingerprint {
		t.Errorf("identical inputs produced different fingerprints: %s vs %s", p1.Fingerprint, p2.Fingerprint)
	}
}

func TestPlan_FingerprintChangesWithState(t *testing.T) {
	p1 := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())

	changed := sampleRepoPlans()
	changed[0].StateHash = "different-hash"
	p2 := plan.New("policy.yaml", "policy-hash-1", changed)

	if p1.Fingerprint == p2.Fingerprint {
		t.Error("fingerprint should change when a repo's recorded state hash changes")
	}
}

func TestPlan_FingerprintChangesWithPolicy(t *testing.T) {
	p1 := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())
	p2 := plan.New("policy.yaml", "policy-hash-2", sampleRepoPlans())

	if p1.Fingerprint == p2.Fingerprint {
		t.Error("fingerprint should change when the policy hash changes")
	}
}

func TestPlan_SaveLoadRoundTrip(t *testing.T) {
	p := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())

	path := filepath.Join(t.TempDir(), "plan.json")
	if err := p.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := plan.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Fingerprint != p.Fingerprint {
		t.Errorf("round-tripped plan has a different fingerprint: %s vs %s", loaded.Fingerprint, p.Fingerprint)
	}
	if len(loaded.Repos) != len(p.Repos) {
		t.Errorf("round-tripped plan has %d repos, want %d", len(loaded.Repos), len(p.Repos))
	}
}

func TestPlan_LoadRejectsTamperedFile(t *testing.T) {
	p := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := p.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Hand-edit the saved file without recomputing the fingerprint —
	// simulates a corrupted or maliciously modified plan.json.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(data), `"repo": "repo-a"`, `"repo": "repo-a-tampered"`, 1))
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := plan.Load(path); err == nil {
		t.Error("expected Load to reject a plan whose contents no longer match its fingerprint")
	}
}

func TestPlan_CheckFresh_DetectsStaleRepo(t *testing.T) {
	p := plan.New("policy.yaml", "policy-hash-1", sampleRepoPlans())

	fresh := map[string]string{"hegarty/repo-a": "hash-a", "hegarty/repo-b": "hash-b"}
	if err := p.CheckFresh(fresh); err != nil {
		t.Errorf("expected no staleness error when hashes match, got %v", err)
	}

	stale := map[string]string{"hegarty/repo-a": "hash-a-CHANGED", "hegarty/repo-b": "hash-b"}
	err := p.CheckFresh(stale)
	if err == nil {
		t.Fatal("expected a staleness error when a repo's live state hash no longer matches the plan")
	}
	var staleErr *plan.StaleReposError
	if !asStaleErr(err, &staleErr) {
		t.Fatalf("expected a *StaleReposError, got %T: %v", err, err)
	}
	if len(staleErr.Repos) != 1 || staleErr.Repos[0] != "hegarty/repo-a" {
		t.Errorf("expected exactly repo-a flagged stale, got %v", staleErr.Repos)
	}
}

func asStaleErr(err error, target **plan.StaleReposError) bool {
	e, ok := err.(*plan.StaleReposError)
	if ok {
		*target = e
	}
	return ok
}

func TestHashState_Deterministic(t *testing.T) {
	type sample struct {
		A string
		B int
	}
	h1, err := plan.HashState(sample{A: "x", B: 1})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := plan.HashState(sample{A: "x", B: 1})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("HashState is not deterministic for identical input: %s vs %s", h1, h2)
	}
	h3, _ := plan.HashState(sample{A: "x", B: 2})
	if h1 == h3 {
		t.Error("HashState should differ for different input")
	}
}
