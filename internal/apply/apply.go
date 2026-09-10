// Package apply executes a Plan's Changes against the GitHub API. Every
// operation must be idempotent: running apply twice against an
// already-converged repo should be a no-op, not an error or a duplicate.
package apply

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/policy"
	"github.com/hegarty/github_policy-as-code/internal/workflows"
)

// Result records the outcome of applying one Change.
type Result struct {
	Change policy.Change
	Err    error
}

// Apply executes every change for one repo, in order, stopping at the first
// error (later changes may implicitly depend on earlier ones, e.g. a
// ruleset referencing a status check that must exist first).
func Apply(ctx context.Context, c ghapi.Client, owner, repo string, changes []policy.Change) []Result {
	results := make([]Result, 0, len(changes))
	for _, ch := range changes {
		err := applyOne(ctx, c, owner, repo, ch)
		results = append(results, Result{Change: ch, Err: err})
		if err != nil {
			break
		}
	}
	return results
}

func applyOne(ctx context.Context, c ghapi.Client, owner, repo string, ch policy.Change) error {
	switch ch.Kind {
	case policy.KindSetDefaultWorkflowPermissions:
		perms, _ := ch.Params["permissions"].(string)
		canApprove, _ := ch.Params["can_approve_pull_request_reviews"].(bool)
		return c.SetDefaultWorkflowPermissions(ctx, owner, repo, perms, canApprove)

	case policy.KindCreateOrUpdateRuleset:
		return applyRuleset(ctx, c, owner, repo, ch.Params)

	case policy.KindInstallTruffleHogWorkflow:
		return applyTruffleHogWorkflow(ctx, c, owner, repo, ch.Params)

	case policy.KindInstallTruffleHogOnboarding:
		return applyTruffleHogOnboarding(ctx, c, owner, repo, ch.Params)

	case policy.KindInstallCIWorkflow:
		return applyCIWorkflow(ctx, c, owner, repo, ch.Params)

	case policy.KindEnableVulnerabilityAlerts:
		return c.EnableVulnerabilityAlerts(ctx, owner, repo)

	case policy.KindEnableAutomatedSecurityFixes:
		return c.EnableAutomatedSecurityFixes(ctx, owner, repo)

	case policy.KindEnableSecretScanningValidity:
		return c.SetSecretScanningValidityChecks(ctx, owner, repo, true)

	case policy.KindEnableSecretScanning:
		return c.EnableSecretScanning(ctx, owner, repo)

	case policy.KindEnableSecretScanningPushProt:
		return c.EnableSecretScanningPushProtection(ctx, owner, repo)

	case policy.KindEnableCodeQL:
		lang, _ := ch.Params["language"].(string)
		return c.EnableCodeScanningDefaultSetup(ctx, owner, repo, lang)

	case policy.KindInstallDependabotConfig:
		lang, _ := ch.Params["language"].(string)
		branch, _ := ch.Params["branch"].(string)
		return applyDependabotConfig(ctx, c, owner, repo, branch, lang)

	default:
		return fmt.Errorf("unknown change kind %q", ch.Kind)
	}
}

func applyRuleset(ctx context.Context, c ghapi.Client, owner, repo string, params map[string]any) error {
	branch, _ := params["branch"].(string)
	enforcement, _ := params["enforcement"].(string)
	reviewCount := 0
	if v, ok := params["required_approving_reviews"].(float64); ok {
		reviewCount = int(v)
	} else if v, ok := params["required_approving_reviews"].(int); ok {
		reviewCount = v
	}
	requireSigned, _ := params["require_signed_commits"].(bool)
	blockForcePush, _ := params["block_force_push"].(bool)
	blockDeletion, _ := params["block_deletion"].(bool)
	linearHistory, _ := params["require_linear_history"].(bool)
	conversationResolution, _ := params["require_conversation_resolution"].(bool)

	var statusChecks []map[string]string
	if raw, ok := params["required_status_checks"]; ok {
		if list, ok := raw.([]any); ok {
			for _, ctxName := range list {
				if s, ok := ctxName.(string); ok {
					statusChecks = append(statusChecks, map[string]string{"context": s})
				}
			}
		} else if list, ok := raw.([]string); ok {
			for _, s := range list {
				statusChecks = append(statusChecks, map[string]string{"context": s})
			}
		}
	}

	rules := []map[string]any{
		{
			"type": "pull_request",
			"parameters": map[string]any{
				"required_approving_review_count":   reviewCount,
				"dismiss_stale_reviews_on_push":     true,
				"require_code_owner_review":         false,
				"require_last_push_approval":        false,
				"required_review_thread_resolution": conversationResolution,
			},
		},
	}
	if requireSigned {
		rules = append(rules, map[string]any{"type": "required_signatures"})
	}
	if blockForcePush {
		rules = append(rules, map[string]any{"type": "non_fast_forward"})
	}
	if blockDeletion {
		rules = append(rules, map[string]any{"type": "deletion"})
	}
	if linearHistory {
		rules = append(rules, map[string]any{"type": "required_linear_history"})
	}
	if len(statusChecks) > 0 {
		rules = append(rules, map[string]any{
			"type": "required_status_checks",
			"parameters": map[string]any{
				"required_status_checks":               statusChecks,
				"strict_required_status_checks_policy": true,
			},
		})
	}

	conditions := map[string]any{
		"ref_name": map[string]any{
			"include": []string{"refs/heads/" + branch},
			"exclude": []string{},
		},
	}

	// Repository-admin role bypass, retained so the owner is never locked
	// out of their own trunk. Role ID 5 is GitHub's built-in "Repository
	// admin" role.
	bypass := []map[string]any{
		{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
	}

	rulesJSON, _ := json.Marshal(rules)
	conditionsJSON, _ := json.Marshal(conditions)
	bypassJSON, _ := json.Marshal(bypass)

	spec := ghapi.RulesetSpec{
		Name:         "main-trunk-protection",
		Target:       "branch",
		Enforcement:  enforcement,
		Conditions:   conditionsJSON,
		Rules:        rulesJSON,
		BypassActors: bypassJSON,
	}
	return c.CreateOrUpdateRuleset(ctx, owner, repo, spec)
}

func applyTruffleHogWorkflow(ctx context.Context, c ghapi.Client, owner, repo string, params map[string]any) error {
	checkoutSHA, _ := params["checkout_sha"].(string)
	trufflehogSHA, _ := params["trufflehog_sha"].(string)
	branch, _ := params["branch"].(string)
	failOnUnverified, _ := params["fail_on_unverified"].(bool)
	if branch == "" {
		branch = "main"
	}
	content := workflows.RenderTruffleHog(workflows.TruffleHogParams{
		CheckoutSHA:      checkoutSHA,
		TruffleHogSHA:    trufflehogSHA,
		FailOnUnverified: failOnUnverified,
		DefaultBranch:    branch,
	})
	return c.CreateOrUpdateFile(ctx, owner, repo, trufflehogWorkflowPath, branch, "ci: install TruffleHog secret scanning", []byte(content))
}

func applyTruffleHogOnboarding(ctx context.Context, c ghapi.Client, owner, repo string, params map[string]any) error {
	checkoutSHA, _ := params["checkout_sha"].(string)
	trufflehogSHA, _ := params["trufflehog_sha"].(string)
	branch, _ := params["branch"].(string)
	if branch == "" {
		branch = "main"
	}
	content := workflows.RenderTruffleHogFullHistory(workflows.TruffleHogFullHistoryParams{
		CheckoutSHA:   checkoutSHA,
		TruffleHogSHA: trufflehogSHA,
	})
	return c.CreateOrUpdateFile(ctx, owner, repo, trufflehogOnboardingWorkflowPath, branch, "ci: add one-time TruffleHog full-history scan", []byte(content))
}

func applyCIWorkflow(ctx context.Context, c ghapi.Client, owner, repo string, params map[string]any) error {
	checkoutSHA, _ := params["checkout_sha"].(string)
	setupGoSHA, _ := params["setup_go_sha"].(string)
	branch, _ := params["branch"].(string)
	if branch == "" {
		branch = "main"
	}
	content := workflows.RenderCI(workflows.CIParams{
		CheckoutSHA:   checkoutSHA,
		SetupGoSHA:    setupGoSHA,
		DefaultBranch: branch,
	})
	return c.CreateOrUpdateFile(ctx, owner, repo, ciWorkflowPath, branch, "ci: add Go build/vet/test workflow", []byte(content))
}

func applyDependabotConfig(ctx context.Context, c ghapi.Client, owner, repo, branch, language string) error {
	if branch == "" {
		branch = "main"
	}
	content := renderDependabotConfig(language)
	return c.CreateOrUpdateFile(ctx, owner, repo, dependabotConfigPath, branch, "chore: add Dependabot config", []byte(content))
}

func renderDependabotConfig(language string) string {
	ecosystem := "github-actions"
	extra := ""
	switch language {
	case "Go":
		extra = `
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"`
	case "JavaScript", "TypeScript":
		extra = `
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"`
	case "Python":
		extra = `
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"`
	}
	return fmt.Sprintf(`version: 2
updates:
  - package-ecosystem: %q
    directory: "/"
    schedule:
      interval: "weekly"%s
`, ecosystem, extra)
}

const (
	trufflehogWorkflowPath           = ".github/workflows/trufflehog.yml"
	trufflehogOnboardingWorkflowPath = ".github/workflows/trufflehog-full-history.yml"
	ciWorkflowPath                   = ".github/workflows/ci.yml"
	dependabotConfigPath             = ".github/dependabot.yml"
)
