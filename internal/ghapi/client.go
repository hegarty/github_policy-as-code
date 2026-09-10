package ghapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const apiBase = "https://api.github.com"

// Client is the full surface the controller needs against the GitHub REST
// API. It is deliberately narrow and owner-agnostic: every method takes
// owner/repo explicitly rather than assuming a fixed account.
type Client interface {
	// Read operations (used by audit/plan).
	GetRepo(ctx context.Context, owner, repo string) (*RepoMeta, error)
	ListCollaborators(ctx context.Context, owner, repo string) ([]Collaborator, error)
	ListRulesets(ctx context.Context, owner, repo string) ([]Ruleset, error)
	GetBranchProtection(ctx context.Context, owner, repo, branch string) (*BranchProtection, error)
	GetDefaultWorkflowPermissions(ctx context.Context, owner, repo string) (perms string, canApprove bool, err error)
	ListWorkflowFiles(ctx context.Context, owner, repo string) ([]WorkflowFile, error)
	VulnerabilityAlertsEnabled(ctx context.Context, owner, repo string) (bool, error)
	DependabotConfigPresent(ctx context.Context, owner, repo string) (bool, error)
	CodeScanningConfigured(ctx context.Context, owner, repo string) (bool, error)
	CountWebhooks(ctx context.Context, owner, repo string) (int, error)
	CountDeployKeys(ctx context.Context, owner, repo string) (int, error)
	// ResolveRef resolves a branch, tag, or existing SHA to its current full
	// commit SHA, for pinning third-party Actions to immutable references.
	ResolveRef(ctx context.Context, owner, repo, ref string) (string, error)

	// Owner-scoped operations, used to resolve --owner into a repo list
	// without hardcoding whether the owner is a user or an organization.
	GetOwnerType(ctx context.Context, owner string) (string, error)
	ListRepoNames(ctx context.Context, owner, ownerType string) ([]RepoSummary, error)

	// Write operations (used by apply). All must be idempotent.
	SetDefaultWorkflowPermissions(ctx context.Context, owner, repo, perms string, canApprove bool) error
	CreateOrUpdateRuleset(ctx context.Context, owner, repo string, rs RulesetSpec) error
	CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) error
	EnableVulnerabilityAlerts(ctx context.Context, owner, repo string) error
	EnableAutomatedSecurityFixes(ctx context.Context, owner, repo string) error
	SetSecretScanningValidityChecks(ctx context.Context, owner, repo string, enabled bool) error
	EnableSecretScanning(ctx context.Context, owner, repo string) error
	EnableSecretScanningPushProtection(ctx context.Context, owner, repo string) error
	EnableCodeScanningDefaultSetup(ctx context.Context, owner, repo, language string) error
	RegisterSSHSigningKey(ctx context.Context, title, publicKey string) error
	CreateRepo(ctx context.Context, owner, ownerType, name, visibility string) error
}

type RepoSummary struct {
	Name     string
	Archived bool
	Fork     bool
}

// RepoMeta is the subset of GET /repos/{owner}/{repo} the controller reads.
type RepoMeta struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Visibility    string `json:"visibility"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Language      string `json:"language"`
	Owner         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	SecurityAndAnalysis struct {
		SecretScanning               statusField `json:"secret_scanning"`
		SecretScanningPushProtection statusField `json:"secret_scanning_push_protection"`
		SecretScanningValidityChecks statusField `json:"secret_scanning_validity_checks"`
		DependabotSecurityUpdates    statusField `json:"dependabot_security_updates"`
	} `json:"security_and_analysis"`
}

type statusField struct {
	Status string `json:"status"`
}

type RulesetSpec struct {
	Name         string          `json:"name"`
	Target       string          `json:"target"`
	Enforcement  string          `json:"enforcement"`
	Conditions   json.RawMessage `json:"conditions"`
	Rules        json.RawMessage `json:"rules"`
	BypassActors json.RawMessage `json:"bypass_actors"`
}

// TokenSource resolves the GitHub API token to use. Prefer an explicit
// GITHUB_TOKEN env var; fall back to the currently authenticated gh CLI
// session so the controller can reuse a developer's existing credential
// without ever having a token pasted into config.
func TokenFromGHCLI() (string, error) {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return "", fmt.Errorf("resolving token from gh CLI: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

type restClient struct {
	token      string
	httpClient *http.Client
}

func NewClient(token string) Client {
	return &restClient{
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *restClient) do(ctx context.Context, method, path string, body any, out any) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode >= 400 {
		return resp, &APIError{StatusCode: resp.StatusCode, Path: path, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("decoding response from %s: %w", path, err)
		}
	}
	return resp, nil
}

type APIError struct {
	StatusCode int
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API %s -> HTTP %d: %s", e.Path, e.StatusCode, e.Body)
}

func (e *APIError) NotFound() bool { return e.StatusCode == 404 }

func IsNotFound(err error) bool {
	var apiErr *APIError
	if ok := asAPIError(err, &apiErr); ok {
		return apiErr.NotFound()
	}
	return false
}

func asAPIError(err error, target **APIError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*APIError); ok {
		*target = e
		return true
	}
	return false
}

func (c *restClient) GetRepo(ctx context.Context, owner, repo string) (*RepoMeta, error) {
	var m RepoMeta
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", owner, repo), nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *restClient) ListCollaborators(ctx context.Context, owner, repo string) ([]Collaborator, error) {
	var raw []struct {
		Login       string          `json:"login"`
		Permissions map[string]bool `json:"permissions"`
	}
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/collaborators?affiliation=direct", owner, repo), nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Collaborator, 0, len(raw))
	for _, r := range raw {
		out = append(out, Collaborator{Login: r.Login, Permissions: r.Permissions})
	}
	return out, nil
}

func (c *restClient) ListRulesets(ctx context.Context, owner, repo string) ([]Ruleset, error) {
	var summaries []struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Target      string `json:"target"`
		Enforcement string `json:"enforcement"`
	}
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/rulesets", owner, repo), nil, &summaries); err != nil {
		return nil, err
	}
	out := make([]Ruleset, 0, len(summaries))
	for _, s := range summaries {
		var detail struct {
			Conditions struct {
				RefName struct {
					Include []string `json:"include"`
				} `json:"ref_name"`
			} `json:"conditions"`
			Rules []struct {
				Type string `json:"type"`
			} `json:"rules"`
			BypassActors []struct {
				ActorType  string `json:"actor_type"`
				ActorID    int64  `json:"actor_id"`
				BypassMode string `json:"bypass_mode"`
			} `json:"bypass_actors"`
		}
		if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/rulesets/%d", owner, repo, s.ID), nil, &detail); err != nil {
			// Fall back to the summary-only entry rather than failing the
			// whole audit over one ruleset's detail call.
			out = append(out, Ruleset{ID: s.ID, Name: s.Name, Target: s.Target, Enforcement: s.Enforcement})
			continue
		}
		rs := Ruleset{
			ID: s.ID, Name: s.Name, Target: s.Target, Enforcement: s.Enforcement,
			RefInclude: detail.Conditions.RefName.Include,
		}
		for _, r := range detail.Rules {
			rs.RuleTypes = append(rs.RuleTypes, r.Type)
		}
		for _, b := range detail.BypassActors {
			rs.BypassActors = append(rs.BypassActors, BypassActor{ActorType: b.ActorType, ActorID: b.ActorID, Mode: b.BypassMode})
		}
		out = append(out, rs)
	}
	return out, nil
}

func (c *restClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*BranchProtection, error) {
	var raw struct {
		RequiredPullRequestReviews *struct {
			RequiredApprovingReviewCount int `json:"required_approving_review_count"`
		} `json:"required_pull_request_reviews"`
		RequiredSignatures *struct {
			Enabled bool `json:"enabled"`
		} `json:"required_signatures"`
		AllowForcePushes *struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_force_pushes"`
		AllowDeletions *struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_deletions"`
		RequiredStatusChecks *struct {
			Contexts []string `json:"contexts"`
		} `json:"required_status_checks"`
	}
	resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch), nil, &raw)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	_ = resp
	bp := &BranchProtection{}
	if raw.RequiredPullRequestReviews != nil {
		bp.RequirePullRequest = true
		bp.RequiredReviewCount = raw.RequiredPullRequestReviews.RequiredApprovingReviewCount
	}
	if raw.RequiredSignatures != nil {
		bp.RequireSignedCommits = raw.RequiredSignatures.Enabled
	}
	if raw.AllowForcePushes != nil {
		bp.BlockForcePush = !raw.AllowForcePushes.Enabled
	}
	if raw.AllowDeletions != nil {
		bp.BlockDeletion = !raw.AllowDeletions.Enabled
	}
	if raw.RequiredStatusChecks != nil {
		bp.RequiredStatusChecks = raw.RequiredStatusChecks.Contexts
	}
	return bp, nil
}

func (c *restClient) GetDefaultWorkflowPermissions(ctx context.Context, owner, repo string) (string, bool, error) {
	var raw struct {
		DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
		CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	}
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/actions/permissions/workflow", owner, repo), nil, &raw); err != nil {
		return "", false, err
	}
	return raw.DefaultWorkflowPermissions, raw.CanApprovePullRequestReviews, nil
}

func (c *restClient) ListWorkflowFiles(ctx context.Context, owner, repo string) ([]WorkflowFile, error) {
	var raw []struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/.github/workflows", owner, repo), nil, &raw)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]WorkflowFile, 0, len(raw))
	for _, f := range raw {
		var content struct {
			Content string `json:"content"`
		}
		if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, f.Path), nil, &content); err != nil {
			continue
		}
		decoded, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
		out = append(out, WorkflowFile{Path: f.Path, Content: string(decoded)})
	}
	return out, nil
}

func (c *restClient) VulnerabilityAlertsEnabled(ctx context.Context, owner, repo string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/vulnerability-alerts", owner, repo), nil, nil)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return resp.StatusCode == 204, nil
}

func (c *restClient) DependabotConfigPresent(ctx context.Context, owner, repo string) (bool, error) {
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/.github/dependabot.yml", owner, repo), nil, nil)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *restClient) CodeScanningConfigured(ctx context.Context, owner, repo string) (bool, error) {
	var raw struct {
		State string `json:"state"`
	}
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/code-scanning/default-setup", owner, repo), nil, &raw)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return raw.State == "configured", nil
}

func (c *restClient) CountWebhooks(ctx context.Context, owner, repo string) (int, error) {
	var raw []json.RawMessage
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/hooks", owner, repo), nil, &raw); err != nil {
		if IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	return len(raw), nil
}

func (c *restClient) ResolveRef(ctx context.Context, owner, repo, ref string) (string, error) {
	var raw struct {
		SHA string `json:"sha"`
	}
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, ref), nil, &raw); err != nil {
		return "", err
	}
	return raw.SHA, nil
}

func (c *restClient) CountDeployKeys(ctx context.Context, owner, repo string) (int, error) {
	var raw []json.RawMessage
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/keys", owner, repo), nil, &raw); err != nil {
		if IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	return len(raw), nil
}

// --- Mutations ---

func (c *restClient) SetDefaultWorkflowPermissions(ctx context.Context, owner, repo, perms string, canApprove bool) error {
	body := map[string]any{
		"default_workflow_permissions":     perms,
		"can_approve_pull_request_reviews": canApprove,
	}
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/actions/permissions/workflow", owner, repo), body, nil)
	return err
}

func (c *restClient) CreateOrUpdateRuleset(ctx context.Context, owner, repo string, rs RulesetSpec) error {
	existing, err := c.ListRulesets(ctx, owner, repo)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Name == rs.Name {
			_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/rulesets/%d", owner, repo, e.ID), rs, nil)
			return err
		}
	}
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/rulesets", owner, repo), rs, nil)
	return err
}

func (c *restClient) CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) error {
	var existing struct {
		SHA string `json:"sha"`
	}
	resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, branch), nil, &existing)
	sha := ""
	if err == nil && resp != nil {
		sha = existing.SHA
	} else if err != nil && !IsNotFound(err) {
		return err
	}
	body := map[string]any{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	if sha != "" {
		body["sha"] = sha
	}
	_, err = c.do(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path), body, nil)
	return err
}

func (c *restClient) EnableVulnerabilityAlerts(ctx context.Context, owner, repo string) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/vulnerability-alerts", owner, repo), nil, nil)
	return err
}

func (c *restClient) EnableAutomatedSecurityFixes(ctx context.Context, owner, repo string) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/%s/automated-security-fixes", owner, repo), nil, nil)
	return err
}

// SetSecretScanningValidityChecks was observed against a live Free-plan
// personal account to return HTTP 200 without actually changing the
// setting — GitHub accepts the PATCH but silently no-ops it, unlike the
// ruleset evaluate-mode case which correctly returns a 422. This looks like
// a plan-tier gate (validity checks build on secret scanning and may
// require GitHub Advanced Security / the paid Secret Protection product)
// that GitHub doesn't surface as an explicit error for this field. Calling
// code should not assume success implies the setting took effect; verify
// via GetRepo if this matters for a given call site.
func (c *restClient) SetSecretScanningValidityChecks(ctx context.Context, owner, repo string, enabled bool) error {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	body := map[string]any{
		"security_and_analysis": map[string]any{
			"secret_scanning_validity_checks": map[string]string{"status": status},
		},
	}
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s", owner, repo), body, nil)
	return err
}

func (c *restClient) EnableSecretScanning(ctx context.Context, owner, repo string) error {
	body := map[string]any{
		"security_and_analysis": map[string]any{
			"secret_scanning": map[string]string{"status": "enabled"},
		},
	}
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s", owner, repo), body, nil)
	return err
}

func (c *restClient) EnableSecretScanningPushProtection(ctx context.Context, owner, repo string) error {
	body := map[string]any{
		"security_and_analysis": map[string]any{
			"secret_scanning_push_protection": map[string]string{"status": "enabled"},
		},
	}
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s", owner, repo), body, nil)
	return err
}

func (c *restClient) EnableCodeScanningDefaultSetup(ctx context.Context, owner, repo, language string) error {
	body := map[string]any{
		"state":     "configured",
		"languages": []string{language},
	}
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s/code-scanning/default-setup", owner, repo), body, nil)
	return err
}

func (c *restClient) RegisterSSHSigningKey(ctx context.Context, title, publicKey string) error {
	body := map[string]string{"title": title, "key": publicKey}
	_, err := c.do(ctx, http.MethodPost, "/user/ssh_signing_keys", body, nil)
	return err
}

func (c *restClient) GetOwnerType(ctx context.Context, owner string) (string, error) {
	var raw struct {
		Type string `json:"type"`
	}
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/users/%s", owner), nil, &raw); err != nil {
		return "", err
	}
	return raw.Type, nil
}

func (c *restClient) ListRepoNames(ctx context.Context, owner, ownerType string) ([]RepoSummary, error) {
	path := fmt.Sprintf("/users/%s/repos?per_page=100&type=owner", owner)
	if ownerType == "Organization" {
		path = fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", owner)
	}
	var raw []struct {
		Name     string `json:"name"`
		Archived bool   `json:"archived"`
		Fork     bool   `json:"fork"`
	}
	if _, err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]RepoSummary, 0, len(raw))
	for _, r := range raw {
		out = append(out, RepoSummary{Name: r.Name, Archived: r.Archived, Fork: r.Fork})
	}
	return out, nil
}

func (c *restClient) CreateRepo(ctx context.Context, owner, ownerType, name, visibility string) error {
	private := visibility != "public"
	body := map[string]any{
		"name":    name,
		"private": private,
	}
	path := "/user/repos"
	if ownerType == "Organization" {
		path = fmt.Sprintf("/orgs/%s/repos", owner)
	}
	_, err := c.do(ctx, http.MethodPost, path, body, nil)
	return err
}
