// Package config loads and validates the security-policy.yaml file that
// drives audit, plan, and apply.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version       int               `yaml:"version"`
	Repositories  RepositoriesSpec  `yaml:"repositories"`
	Trunk         TrunkSpec         `yaml:"trunk"`
	DefaultBranch DefaultBranchSpec `yaml:"default_branch"`
	Actions       ActionsSpec       `yaml:"actions"`
	Security      SecuritySpec      `yaml:"security"`
	Deployment    DeploymentSpec    `yaml:"deployment"`
}

type RepositoriesSpec struct {
	Visibility string `yaml:"visibility"` // "public" (default) or "private"
}

type TrunkSpec struct {
	Branch           string `yaml:"branch"`
	RequireAsDefault bool   `yaml:"require_as_default"`
}

type ReviewCountSpec struct {
	SoloMaintainer  int `yaml:"solo_maintainer"`
	MultiMaintainer int `yaml:"multi_maintainer"`
}

type BypassActor struct {
	Role string `yaml:"role"` // e.g. "repository_admin"
}

type DefaultBranchSpec struct {
	RequirePullRequest            bool            `yaml:"require_pull_request"`
	RequireSignedCommits          bool            `yaml:"require_signed_commits"`
	BlockForcePush                bool            `yaml:"block_force_push"`
	BlockDeletion                 bool            `yaml:"block_deletion"`
	RequireStatusChecks           bool            `yaml:"require_status_checks"`
	RequiredStatusCheckContexts   []string        `yaml:"required_status_check_contexts"`
	RequireConversationResolution bool            `yaml:"require_conversation_resolution"`
	RequireLinearHistory          bool            `yaml:"require_linear_history"`
	RequiredApprovingReviewCount  ReviewCountSpec `yaml:"required_approving_review_count"`
	BypassActors                  []BypassActor   `yaml:"bypass_actors"`
	Enforcement                   string          `yaml:"enforcement"` // "evaluate" or "active"
}

type ActionsSpec struct {
	DefaultTokenPermissions string `yaml:"default_token_permissions"` // "read" or "write"
	PinActionsToSHA         bool   `yaml:"pin_actions_to_sha"`
}

type TruffleHogSpec struct {
	Enabled                     bool   `yaml:"enabled"`
	RequiredOnPullRequests      bool   `yaml:"required_on_pull_requests"`
	RunOnPRUpdates              bool   `yaml:"run_on_pr_updates"`
	RequiredStatusCheck         bool   `yaml:"required_status_check"`
	FullHistoryScanOnOnboarding bool   `yaml:"full_history_scan_on_onboarding"`
	ScanMode                    string `yaml:"scan_mode"` // "diff" or "full"
	FailOnVerifiedSecret        bool   `yaml:"fail_on_verified_secret"`
	FailOnUnverifiedSecret      bool   `yaml:"fail_on_unverified_secret"`
}

type CodeQLSpec struct {
	Enabled      string `yaml:"enabled"`       // "auto", "always", "never"
	PrivateRepos bool   `yaml:"private_repos"` // never auto-enable paid features unless true
}

type SecuritySpec struct {
	GitHubSecretScanning bool           `yaml:"github_secret_scanning"`
	GitHubPushProtection bool           `yaml:"github_push_protection"`
	Dependabot           bool           `yaml:"dependabot"`
	CodeQL               CodeQLSpec     `yaml:"codeql"`
	TruffleHog           TruffleHogSpec `yaml:"trufflehog"`
}

type DeploymentSpec struct {
	AllowFromTrunkOnly bool   `yaml:"allow_from_trunk_only"`
	TrunkBranch        string `yaml:"trunk_branch"`
}

// Load reads and validates a security-policy.yaml file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, nil
}

// Default returns the baseline policy used when no --policy file is given:
// solo-maintainer-aware review counts, evaluate-mode rulesets (staged
// rollout before active enforcement), TruffleHog required on PRs failing on
// both verified and unverified secrets, and CodeQL auto-enabled only for
// eligible languages on public repos.
func Default() *Policy {
	return &Policy{
		Version:      1,
		Repositories: RepositoriesSpec{Visibility: "public"},
		Trunk:        TrunkSpec{Branch: "main", RequireAsDefault: true},
		DefaultBranch: DefaultBranchSpec{
			RequirePullRequest:            true,
			RequireSignedCommits:          true,
			BlockForcePush:                true,
			BlockDeletion:                 true,
			RequireStatusChecks:           true,
			RequiredStatusCheckContexts:   []string{"trufflehog", "build"},
			RequireConversationResolution: true,
			RequireLinearHistory:          true,
			RequiredApprovingReviewCount:  ReviewCountSpec{SoloMaintainer: 0, MultiMaintainer: 1},
			BypassActors:                  []BypassActor{{Role: "repository_admin"}},
			Enforcement:                   "evaluate",
		},
		Actions: ActionsSpec{
			DefaultTokenPermissions: "read",
			PinActionsToSHA:         true,
		},
		Security: SecuritySpec{
			GitHubSecretScanning: true,
			GitHubPushProtection: true,
			Dependabot:           true,
			CodeQL:               CodeQLSpec{Enabled: "auto", PrivateRepos: false},
			TruffleHog: TruffleHogSpec{
				Enabled:                     true,
				RequiredOnPullRequests:      true,
				RunOnPRUpdates:              true,
				RequiredStatusCheck:         true,
				FullHistoryScanOnOnboarding: true,
				ScanMode:                    "diff",
				FailOnVerifiedSecret:        true,
				FailOnUnverifiedSecret:      true,
			},
		},
		Deployment: DeploymentSpec{
			AllowFromTrunkOnly: true,
			TrunkBranch:        "main",
		},
	}
}

func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d (expected 1)", p.Version)
	}
	if p.Trunk.Branch == "" {
		return fmt.Errorf("trunk.branch must be set")
	}
	if p.Security.TruffleHog.Enabled && p.Security.TruffleHog.ScanMode == "" {
		return fmt.Errorf("security.trufflehog.scan_mode must be set when trufflehog is enabled")
	}
	switch p.DefaultBranch.Enforcement {
	case "", "evaluate", "active":
	default:
		return fmt.Errorf("default_branch.enforcement must be 'evaluate' or 'active', got %q", p.DefaultBranch.Enforcement)
	}
	switch p.Security.CodeQL.Enabled {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("security.codeql.enabled must be 'auto', 'always', or 'never', got %q", p.Security.CodeQL.Enabled)
	}
	return nil
}
