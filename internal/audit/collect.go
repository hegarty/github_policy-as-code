// Package audit performs read-only collection of a repository's live state
// from the GitHub API into a ghapi.RepoState the policy engine can evaluate.
// Nothing in this package ever mutates GitHub state.
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
)

// Collect builds a normalized RepoState for owner/repo. It never returns
// secret values, only metadata.
func Collect(ctx context.Context, c ghapi.Client, owner, repo string) (*ghapi.RepoState, error) {
	meta, err := c.GetRepo(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("fetching repo metadata: %w", err)
	}

	state := &ghapi.RepoState{
		Owner:           owner,
		OwnerType:       meta.Owner.Type,
		Name:            repo,
		Visibility:      meta.Visibility,
		Archived:        meta.Archived,
		Fork:            meta.Fork,
		DefaultBranch:   meta.DefaultBranch,
		PrimaryLanguage: meta.Language,
		IsEmpty:         meta.DefaultBranch == "",
		FetchedAt:       time.Now().UTC(),

		SecretScanning:               meta.SecurityAndAnalysis.SecretScanning.Status,
		SecretScanningPushProtection: meta.SecurityAndAnalysis.SecretScanningPushProtection.Status,
		SecretScanningValidityChecks: meta.SecurityAndAnalysis.SecretScanningValidityChecks.Status,
		DependabotSecurityUpdates:    meta.SecurityAndAnalysis.DependabotSecurityUpdates.Status,
	}

	if collabs, err := c.ListCollaborators(ctx, owner, repo); err == nil {
		state.Collaborators = collabs
	} else {
		return nil, fmt.Errorf("listing collaborators: %w", err)
	}

	if rulesets, err := c.ListRulesets(ctx, owner, repo); err == nil {
		state.Rulesets = rulesets
	} else {
		return nil, fmt.Errorf("listing rulesets: %w", err)
	}

	if !state.IsEmpty {
		if bp, err := c.GetBranchProtection(ctx, owner, repo, state.DefaultBranch); err == nil {
			state.BranchProtection = bp
		} else {
			return nil, fmt.Errorf("fetching branch protection: %w", err)
		}
	}

	if perms, canApprove, err := c.GetDefaultWorkflowPermissions(ctx, owner, repo); err == nil {
		state.DefaultWorkflowPermissions = perms
		state.CanApprovePRReviews = canApprove
	} else {
		return nil, fmt.Errorf("fetching actions workflow permissions: %w", err)
	}

	if wf, err := c.ListWorkflowFiles(ctx, owner, repo); err == nil {
		state.Workflows = wf
	} else {
		return nil, fmt.Errorf("listing workflow files: %w", err)
	}

	if enabled, err := c.VulnerabilityAlertsEnabled(ctx, owner, repo); err == nil {
		state.VulnerabilityAlertsEnabled = enabled
	} else {
		return nil, fmt.Errorf("checking vulnerability alerts: %w", err)
	}

	if present, err := c.DependabotConfigPresent(ctx, owner, repo); err == nil {
		state.DependabotConfigPresent = present
	} else {
		return nil, fmt.Errorf("checking dependabot config: %w", err)
	}

	if configured, err := c.CodeScanningConfigured(ctx, owner, repo); err == nil {
		state.CodeScanningConfigured = configured
	} else {
		return nil, fmt.Errorf("checking code scanning setup: %w", err)
	}

	if n, err := c.CountWebhooks(ctx, owner, repo); err == nil {
		state.Webhooks = n
	} else {
		return nil, fmt.Errorf("counting webhooks: %w", err)
	}

	if n, err := c.CountDeployKeys(ctx, owner, repo); err == nil {
		state.DeployKeys = n
	} else {
		return nil, fmt.Errorf("counting deploy keys: %w", err)
	}

	return state, nil
}
