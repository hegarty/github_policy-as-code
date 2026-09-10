package ghapi_test

import (
	"testing"
	"time"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
)

// TestForHashing_StripsCollectionTimestamp guards against a real bug: plan
// staleness detection hashes RepoState, and if FetchedAt were included two
// collections of an unchanged repo, seconds apart, would always look
// "stale" to CheckFresh even with zero real drift.
func TestForHashing_StripsCollectionTimestamp(t *testing.T) {
	base := ghapi.RepoState{Owner: "hegarty", Name: "example", DefaultBranch: "main"}

	s1 := base
	s1.FetchedAt = time.Now()
	s2 := base
	s2.FetchedAt = time.Now().Add(time.Hour)

	h1 := s1.ForHashing()
	h2 := s2.ForHashing()

	if h1.FetchedAt != h2.FetchedAt {
		t.Fatalf("ForHashing should zero FetchedAt so it never contributes to a diff, got %v vs %v", h1.FetchedAt, h2.FetchedAt)
	}
	if !h1.FetchedAt.IsZero() {
		t.Errorf("expected FetchedAt to be zeroed, got %v", h1.FetchedAt)
	}
}
