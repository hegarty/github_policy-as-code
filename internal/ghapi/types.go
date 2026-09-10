// Package ghapi provides a typed, owner-agnostic wrapper around the GitHub
// API surface the controller needs, and the normalized RepoState the policy
// engine evaluates against.
package ghapi

import "time"

// RepoState is a normalized, provider-independent snapshot of everything the
// policy engine needs to know about one repository. It intentionally never
// carries secret values, only metadata (names, counts, statuses). JSON tags
// make this the fixture format under testdata/fixtures.
type RepoState struct {
	Owner      string `json:"owner"`
	OwnerType  string `json:"owner_type"` // "User" or "Organization"
	Name       string `json:"name"`
	Visibility string `json:"visibility"` // "public" or "private"
	Archived   bool   `json:"archived"`
	Fork       bool   `json:"fork"`
	IsEmpty    bool   `json:"is_empty"` // true if the repo has zero commits

	DefaultBranch   string `json:"default_branch"`
	PrimaryLanguage string `json:"primary_language"`

	Collaborators []Collaborator `json:"collaborators"`

	Rulesets         []Ruleset         `json:"rulesets"`
	BranchProtection *BranchProtection `json:"branch_protection,omitempty"` // nil if classic protection is absent

	DefaultWorkflowPermissions string         `json:"default_workflow_permissions"` // "read" or "write"
	CanApprovePRReviews        bool           `json:"can_approve_pr_reviews"`
	Workflows                  []WorkflowFile `json:"workflows"`

	SecretScanning               string `json:"secret_scanning"` // "enabled" / "disabled"
	SecretScanningPushProtection string `json:"secret_scanning_push_protection"`
	SecretScanningValidityChecks string `json:"secret_scanning_validity_checks"`
	DependabotSecurityUpdates    string `json:"dependabot_security_updates"`
	VulnerabilityAlertsEnabled   bool   `json:"vulnerability_alerts_enabled"`
	DependabotConfigPresent      bool   `json:"dependabot_config_present"`
	CodeScanningConfigured       bool   `json:"code_scanning_configured"`

	Webhooks   int `json:"webhooks"`
	DeployKeys int `json:"deploy_keys"`

	FetchedAt time.Time `json:"fetched_at"`
}

type Collaborator struct {
	Login       string          `json:"login"`
	Permissions map[string]bool `json:"permissions"`
}

// SoloMaintainer reports whether this repo has exactly one collaborator
// (the owner). Used to select the review-count policy tier.
func (r *RepoState) SoloMaintainer() bool {
	return len(r.Collaborators) <= 1
}

// ForHashing returns a copy of the state with FetchedAt zeroed. Plan
// fingerprints and staleness checks must be based on the repo's actual
// configuration, not on when it happened to be collected — including
// FetchedAt would make every fresh audit look "stale" relative to the plan,
// even with zero real drift.
func (r RepoState) ForHashing() RepoState {
	r.FetchedAt = time.Time{}
	return r
}

type Ruleset struct {
	ID           int64         `json:"id"`
	Name         string        `json:"name"`
	Target       string        `json:"target"`      // "branch" or "tag"
	Enforcement  string        `json:"enforcement"` // "disabled", "evaluate", "active"
	RefInclude   []string      `json:"ref_include"`
	RuleTypes    []string      `json:"rule_types"`
	BypassActors []BypassActor `json:"bypass_actors"`
}

type BypassActor struct {
	ActorType string `json:"actor_type"` // "RepositoryRole", "Team", "Integration", "OrganizationAdmin"
	ActorID   int64  `json:"actor_id"`
	Mode      string `json:"mode"` // "always" or "pull_request"
}

// BranchProtection represents legacy (non-ruleset) branch protection, kept
// for audit visibility since some repos may still use it instead of, or
// alongside, rulesets.
type BranchProtection struct {
	RequirePullRequest   bool     `json:"require_pull_request"`
	RequiredReviewCount  int      `json:"required_review_count"`
	RequireSignedCommits bool     `json:"require_signed_commits"`
	BlockForcePush       bool     `json:"block_force_push"`
	BlockDeletion        bool     `json:"block_deletion"`
	RequiredStatusChecks []string `json:"required_status_checks"`
}

type WorkflowFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"
)
