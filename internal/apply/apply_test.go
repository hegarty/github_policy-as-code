package apply_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/apply"
	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/policy"
)

// mockClient is an in-memory ghapi.Client used to test apply idempotency
// without hitting the real GitHub API. Only the write paths exercised by
// apply.Apply are meaningfully implemented; read paths return zero values.
type mockClient struct {
	rulesets       map[string]ghapi.RulesetSpec // keyed by name
	rulesetCreates int
	rulesetUpdates int
	files          map[string][]byte // keyed by path
	fileWrites     int
	vulnAlertsOn   bool
	secFixesOn     bool
}

func newMockClient() *mockClient {
	return &mockClient{rulesets: map[string]ghapi.RulesetSpec{}, files: map[string][]byte{}}
}

func (m *mockClient) GetRepo(ctx context.Context, owner, repo string) (*ghapi.RepoMeta, error) {
	return &ghapi.RepoMeta{}, nil
}
func (m *mockClient) ListCollaborators(ctx context.Context, owner, repo string) ([]ghapi.Collaborator, error) {
	return nil, nil
}
func (m *mockClient) ListRulesets(ctx context.Context, owner, repo string) ([]ghapi.Ruleset, error) {
	var out []ghapi.Ruleset
	id := int64(1)
	for name := range m.rulesets {
		out = append(out, ghapi.Ruleset{ID: id, Name: name})
		id++
	}
	return out, nil
}
func (m *mockClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*ghapi.BranchProtection, error) {
	return nil, nil
}
func (m *mockClient) GetDefaultWorkflowPermissions(ctx context.Context, owner, repo string) (string, bool, error) {
	return "read", false, nil
}
func (m *mockClient) ListWorkflowFiles(ctx context.Context, owner, repo string) ([]ghapi.WorkflowFile, error) {
	return nil, nil
}
func (m *mockClient) VulnerabilityAlertsEnabled(ctx context.Context, owner, repo string) (bool, error) {
	return m.vulnAlertsOn, nil
}
func (m *mockClient) DependabotConfigPresent(ctx context.Context, owner, repo string) (bool, error) {
	_, ok := m.files[".github/dependabot.yml"]
	return ok, nil
}
func (m *mockClient) CodeScanningConfigured(ctx context.Context, owner, repo string) (bool, error) {
	return false, nil
}
func (m *mockClient) CountWebhooks(ctx context.Context, owner, repo string) (int, error) {
	return 0, nil
}
func (m *mockClient) CountDeployKeys(ctx context.Context, owner, repo string) (int, error) {
	return 0, nil
}
func (m *mockClient) ResolveRef(ctx context.Context, owner, repo, ref string) (string, error) {
	return "0000000000000000000000000000000000000000", nil
}
func (m *mockClient) GetOwnerType(ctx context.Context, owner string) (string, error) {
	return "User", nil
}
func (m *mockClient) ListRepoNames(ctx context.Context, owner, ownerType string) ([]ghapi.RepoSummary, error) {
	return nil, nil
}

func (m *mockClient) SetDefaultWorkflowPermissions(ctx context.Context, owner, repo, perms string, canApprove bool) error {
	return nil
}
func (m *mockClient) CreateOrUpdateRuleset(ctx context.Context, owner, repo string, rs ghapi.RulesetSpec) error {
	if _, exists := m.rulesets[rs.Name]; exists {
		m.rulesetUpdates++
	} else {
		m.rulesetCreates++
	}
	m.rulesets[rs.Name] = rs
	return nil
}
func (m *mockClient) CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) error {
	m.fileWrites++
	m.files[path] = content
	return nil
}
func (m *mockClient) EnableVulnerabilityAlerts(ctx context.Context, owner, repo string) error {
	m.vulnAlertsOn = true
	return nil
}
func (m *mockClient) EnableAutomatedSecurityFixes(ctx context.Context, owner, repo string) error {
	m.secFixesOn = true
	return nil
}
func (m *mockClient) SetSecretScanningValidityChecks(ctx context.Context, owner, repo string, enabled bool) error {
	return nil
}
func (m *mockClient) EnableSecretScanning(ctx context.Context, owner, repo string) error { return nil }
func (m *mockClient) EnableSecretScanningPushProtection(ctx context.Context, owner, repo string) error {
	return nil
}
func (m *mockClient) EnableCodeScanningDefaultSetup(ctx context.Context, owner, repo, language string) error {
	return nil
}
func (m *mockClient) RegisterSSHSigningKey(ctx context.Context, title, publicKey string) error {
	return nil
}
func (m *mockClient) CreateRepo(ctx context.Context, owner, ownerType, name, visibility string) error {
	return nil
}

func rulesetChange() policy.Change {
	return policy.Change{
		Repo: "hegarty/example", Control: "ruleset", Kind: policy.KindCreateOrUpdateRuleset,
		Params: map[string]any{
			"name": "main-trunk-protection", "branch": "main", "enforcement": "evaluate",
			"required_approving_reviews": 0, "require_signed_commits": true,
			"block_force_push": true, "block_deletion": true, "require_linear_history": true,
			"require_conversation_resolution": true,
			"required_status_checks":          []string{"trufflehog"},
		},
	}
}

func TestApply_RulesetIsIdempotent(t *testing.T) {
	m := newMockClient()
	ctx := context.Background()

	results := apply.Apply(ctx, m, "hegarty", "example", []policy.Change{rulesetChange()})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("first apply failed: %+v", results)
	}
	if m.rulesetCreates != 1 || m.rulesetUpdates != 0 {
		t.Fatalf("expected 1 create, 0 updates after first apply, got creates=%d updates=%d", m.rulesetCreates, m.rulesetUpdates)
	}

	// Applying the same change again against the now-existing ruleset must
	// update, not duplicate-create.
	results = apply.Apply(ctx, m, "hegarty", "example", []policy.Change{rulesetChange()})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("second apply failed: %+v", results)
	}
	if m.rulesetCreates != 1 || m.rulesetUpdates != 1 {
		t.Fatalf("expected 1 create, 1 update after second apply, got creates=%d updates=%d", m.rulesetCreates, m.rulesetUpdates)
	}
	if len(m.rulesets) != 1 {
		t.Fatalf("expected exactly one ruleset to exist, got %d", len(m.rulesets))
	}
}

func TestApply_TruffleHogWorkflow(t *testing.T) {
	m := newMockClient()
	ctx := context.Background()

	ch := policy.Change{
		Repo: "hegarty/example", Control: "trufflehog", Kind: policy.KindInstallTruffleHogWorkflow,
		Params: map[string]any{
			"checkout_sha":   "1111111111111111111111111111111111111111",
			"trufflehog_sha": "2222222222222222222222222222222222222222",
			"branch":         "main", "fail_on_unverified": true,
		},
	}
	results := apply.Apply(ctx, m, "hegarty", "example", []policy.Change{ch})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("apply failed: %+v", results)
	}
	content, ok := m.files[".github/workflows/trufflehog.yml"]
	if !ok {
		t.Fatal("expected trufflehog.yml to be written")
	}
	if !strings.Contains(string(content), "trufflesecurity/trufflehog@2222222222222222222222222222222222222222") {
		t.Errorf("expected rendered workflow to reference the pinned SHA, got:\n%s", content)
	}
	if !strings.Contains(string(content), "--results=verified,unknown") {
		t.Errorf("expected fail_on_unverified=true to render --results=verified,unknown, got:\n%s", content)
	}
}

func TestApply_StopsAtFirstError(t *testing.T) {
	m := newMockClient()
	ctx := context.Background()

	changes := []policy.Change{
		{Repo: "hegarty/example", Kind: "unknown_kind_x"},
		{Repo: "hegarty/example", Kind: policy.KindEnableVulnerabilityAlerts},
	}
	results := apply.Apply(ctx, m, "hegarty", "example", changes)
	if len(results) != 1 {
		t.Fatalf("expected apply to stop after the first failure, got %d results", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected the unknown-kind change to fail")
	}
	if m.vulnAlertsOn {
		t.Error("second change should never have run after the first failed")
	}
}
