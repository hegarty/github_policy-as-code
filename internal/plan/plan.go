// Package plan turns policy evaluation output into a serializable,
// fingerprinted Plan artifact. The fingerprint binds a plan to the exact
// policy file and live repo state it was computed from, so apply can detect
// drift between planning and applying and refuse to proceed against stale
// assumptions.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/hegarty/github_policy-as-code/internal/policy"
)

type RepoPlan struct {
	Owner     string           `json:"owner"`
	Repo      string           `json:"repo"`
	StateHash string           `json:"state_hash"`
	Findings  []policy.Finding `json:"findings"`
	Changes   []policy.Change  `json:"changes"`
}

type Plan struct {
	Version     int        `json:"version"`
	GeneratedAt time.Time  `json:"generated_at"`
	PolicyPath  string     `json:"policy_path"`
	PolicyHash  string     `json:"policy_hash"`
	Repos       []RepoPlan `json:"repos"`
	Fingerprint string     `json:"fingerprint"`
}

// HashState produces a deterministic hash of any JSON-serializable state.
// Used both for the per-repo state_hash embedded in the plan and, at apply
// time, for the freshly-fetched state to compare against it.
func HashState(v any) (string, error) {
	// json.Marshal on maps is not key-order-stable across Go versions in
	// general, but is for struct fields (declaration order) and for map
	// keys specifically Go's encoding/json sorts map keys alphabetically,
	// which makes this deterministic in practice.
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("hashing state: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func HashPolicyBytes(policyBytes []byte) string {
	sum := sha256.Sum256(policyBytes)
	return hex.EncodeToString(sum[:])
}

// New builds a Plan from per-repo findings/changes/state-hashes and
// computes its overall fingerprint.
func New(policyPath string, policyHash string, repos []RepoPlan) *Plan {
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].Owner != repos[j].Owner {
			return repos[i].Owner < repos[j].Owner
		}
		return repos[i].Repo < repos[j].Repo
	})
	p := &Plan{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		PolicyPath:  policyPath,
		PolicyHash:  policyHash,
		Repos:       repos,
	}
	p.Fingerprint = p.computeFingerprint()
	return p
}

func (p *Plan) computeFingerprint() string {
	h := sha256.New()
	h.Write([]byte(p.PolicyHash))
	for _, r := range p.Repos {
		h.Write([]byte(r.Owner + "/" + r.Repo + ":" + r.StateHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Verify recomputes the fingerprint and reports whether the plan is still
// internally consistent (i.e. hasn't been hand-edited or corrupted).
func (p *Plan) Verify() bool {
	return p.Fingerprint == p.computeFingerprint()
}

// StaleReposError lists which repos' live state no longer matches what the
// plan was computed against.
type StaleReposError struct {
	Repos []string
}

func (e *StaleReposError) Error() string {
	return fmt.Sprintf("plan is stale for %d repo(s): %v — replan before applying", len(e.Repos), e.Repos)
}

// CheckFresh compares the plan's recorded per-repo state hashes against
// freshly computed ones (currentHashes, keyed by "owner/repo") and returns
// StaleReposError if any differ.
func (p *Plan) CheckFresh(currentHashes map[string]string) error {
	var stale []string
	for _, r := range p.Repos {
		key := r.Owner + "/" + r.Repo
		if currentHashes[key] != r.StateHash {
			stale = append(stale, key)
		}
	}
	if len(stale) > 0 {
		return &StaleReposError{Repos: stale}
	}
	return nil
}

func (p *Plan) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parsing plan file: %w", err)
	}
	if !p.Verify() {
		return nil, fmt.Errorf("plan fingerprint mismatch — plan.json may have been hand-edited or corrupted")
	}
	return &p, nil
}
