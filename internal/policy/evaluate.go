package policy

import (
	"fmt"
	"strings"

	"github.com/hegarty/github_policy-as-code/internal/config"
	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/trufflehog"
)

const rulesetName = "main-trunk-protection"

// roleActorIDs maps the policy's human-readable bypass_actors[].role values
// to GitHub's built-in RepositoryRole actor IDs, so live ruleset state
// (which only carries numeric actor IDs) can be compared against policy
// intent (which is expressed in role names for readability). Only
// "repository_admin" (id 5) is verified against current GitHub docs; this
// is the only role the default policy actually uses.
var roleActorIDs = map[string]int64{
	"repository_admin": 5,
}

// codeQLLanguageIDs maps GitHub's repo-metadata language names (Linguist
// style, as returned in RepoState.PrimaryLanguage) to the identifiers the
// code-scanning default-setup API actually accepts — confirmed against a
// live 422 response ("Go" was rejected; the API wants lowercase "go").
// Not exhaustive of every CodeQL build mode, but covers the common cases
// the controller needs to decide "auto" eligibility.
var codeQLLanguageIDs = map[string]string{
	"Go": "go", "JavaScript": "javascript-typescript", "TypeScript": "javascript-typescript",
	"Python": "python", "Ruby": "ruby", "Java": "java-kotlin", "Kotlin": "java-kotlin",
	"C#": "csharp", "C++": "c-cpp", "C": "c-cpp", "Swift": "swift",
}

// Evaluate compares a repo's live state against policy and returns findings
// (what's wrong) and changes (what would fix it). It never mutates
// anything; apply.Apply is what actually calls the GitHub API.
func Evaluate(state *ghapi.RepoState, pol *config.Policy) ([]Finding, []Change) {
	var findings []Finding
	var changes []Change

	repoID := fmt.Sprintf("%s/%s", state.Owner, state.Name)

	if state.IsEmpty {
		findings = append(findings, Finding{
			Repo: repoID, Control: "trunk", Severity: SeverityInfo,
			Message: "repository has no commits yet — trunk/branch policy cannot be evaluated until it is initialized",
		})
		return findings, changes
	}

	if state.DefaultBranch != pol.Trunk.Branch {
		findings = append(findings, Finding{
			Repo: repoID, Control: "trunk", Severity: SeverityInfo,
			Message: fmt.Sprintf("default branch is %q, policy trunk is %q — reported only, not auto-remediated", state.DefaultBranch, pol.Trunk.Branch),
		})
	}

	solo := state.SoloMaintainer()
	desiredReviewCount := pol.DefaultBranch.RequiredApprovingReviewCount.MultiMaintainer
	if solo {
		desiredReviewCount = pol.DefaultBranch.RequiredApprovingReviewCount.SoloMaintainer
	}

	// --- Trunk ruleset ---
	var existing *ghapi.Ruleset
	for i := range state.Rulesets {
		if state.Rulesets[i].Name == rulesetName {
			existing = &state.Rulesets[i]
			break
		}
	}
	enforcement := pol.DefaultBranch.Enforcement
	if enforcement == "" {
		enforcement = "evaluate"
	}
	if existing == nil {
		findings = append(findings, Finding{
			Repo: repoID, Control: "ruleset", Severity: SeverityHigh,
			Message: fmt.Sprintf("no %q ruleset protecting %s — PRs, signed commits, force-push/deletion, and status checks are not enforced", rulesetName, state.DefaultBranch),
		})
		changes = append(changes, rulesetChange(repoID, state.DefaultBranch, "(none)", enforcement, desiredReviewCount, pol, RiskSensitive))
	} else if existing.Enforcement != enforcement {
		sev := SeverityMedium
		risk := RiskSensitive
		if existing.Enforcement == "active" && enforcement == "evaluate" {
			sev = SeverityHigh
			risk = RiskHigh // weakening an active control is high-risk
		}
		findings = append(findings, Finding{
			Repo: repoID, Control: "ruleset", Severity: sev,
			Message: fmt.Sprintf("ruleset %q enforcement is %q, policy wants %q", rulesetName, existing.Enforcement, enforcement),
		})
		changes = append(changes, rulesetChange(repoID, state.DefaultBranch, existing.Enforcement, enforcement, desiredReviewCount, pol, risk))
	}
	if existing != nil {
		findings = append(findings, bypassActorFindings(repoID, existing.BypassActors, pol.DefaultBranch.BypassActors)...)
	}

	// --- Actions default token permissions ---
	if pol.Actions.DefaultTokenPermissions != "" && state.DefaultWorkflowPermissions != pol.Actions.DefaultTokenPermissions {
		risk := RiskSensitive
		sev := SeverityMedium
		if state.DefaultWorkflowPermissions == "read" && pol.Actions.DefaultTokenPermissions == "write" {
			risk = RiskHigh
			sev = SeverityHigh
		}
		findings = append(findings, Finding{
			Repo: repoID, Control: "actions_token_permissions", Severity: sev,
			Message: fmt.Sprintf("default GITHUB_TOKEN permissions are %q, policy wants %q", state.DefaultWorkflowPermissions, pol.Actions.DefaultTokenPermissions),
		})
		changes = append(changes, Change{
			Repo: repoID, Control: "actions_token_permissions",
			Current: state.DefaultWorkflowPermissions, Desired: pol.Actions.DefaultTokenPermissions,
			Action: "set default_workflow_permissions", Risk: risk,
			Impact: "changes default GITHUB_TOKEN scope for all future workflow runs in this repo",
			Kind:   KindSetDefaultWorkflowPermissions,
			Params: map[string]any{"permissions": pol.Actions.DefaultTokenPermissions, "can_approve_pull_request_reviews": false},
		})
	}

	// --- TruffleHog ---
	if pol.Security.TruffleHog.Enabled {
		thState := trufflehog.Inspect(state.Workflows)
		requiredCheckWired := existing != nil // ruleset (once created) references "trufflehog" as a required check
		for _, f := range trufflehog.Evaluate(thState, requiredCheckWired, pol.Security.TruffleHog.FailOnVerifiedSecret, pol.Security.TruffleHog.FailOnUnverifiedSecret) {
			sev := SeverityMedium
			switch f.Severity {
			case "CRITICAL":
				sev = SeverityCritical
			case "HIGH":
				sev = SeverityHigh
			case "LOW":
				sev = SeverityLow
			}
			findings = append(findings, Finding{Repo: repoID, Control: "trufflehog", Severity: sev, Message: f.Message})
		}
		if !thState.Installed {
			changes = append(changes, Change{
				Repo: repoID, Control: "trufflehog",
				Current: "absent", Desired: "installed, diff-mode, fail_on_verified=true",
				Action: "create .github/workflows/trufflehog.yml", Risk: RiskSensitive,
				Impact: "adds a required CI check once the ruleset references it",
				Kind:   KindInstallTruffleHogWorkflow,
				Params: map[string]any{"fail_on_unverified": pol.Security.TruffleHog.FailOnUnverifiedSecret},
			})
			if pol.Security.TruffleHog.FullHistoryScanOnOnboarding {
				changes = append(changes, Change{
					Repo: repoID, Control: "trufflehog_onboarding",
					Current: "absent", Desired: "one-time full-history scan workflow",
					Action: "create .github/workflows/trufflehog-full-history.yml (workflow_dispatch)", Risk: RiskSafe,
					Impact: "manually-triggered only; does not run on every push",
					Kind:   KindInstallTruffleHogOnboarding,
				})
			}
		}
	}

	// --- CI workflow (Go repos only, this version) ---
	if state.PrimaryLanguage == "Go" {
		hasCI := false
		for _, wf := range state.Workflows {
			if containsGoTest(wf.Content) {
				hasCI = true
				break
			}
		}
		if !hasCI {
			changes = append(changes, Change{
				Repo: repoID, Control: "ci",
				Current: "absent", Desired: "go build/vet/test on PR + push",
				Action: "create .github/workflows/ci.yml", Risk: RiskSafe,
				Impact: "adds a required CI check once the ruleset references it",
				Kind:   KindInstallCIWorkflow,
			})
		}
	}

	// --- Dependabot ---
	if pol.Security.Dependabot {
		if !state.VulnerabilityAlertsEnabled {
			findings = append(findings, Finding{Repo: repoID, Control: "dependabot", Severity: SeverityMedium, Message: "Dependabot vulnerability alerts are disabled"})
			changes = append(changes, Change{
				Repo: repoID, Control: "dependabot_alerts", Current: "disabled", Desired: "enabled",
				Action: "enable vulnerability alerts", Risk: RiskSafe, Impact: "alert-only, no auto-merge",
				Kind: KindEnableVulnerabilityAlerts,
			})
		}
		if state.DependabotSecurityUpdates != "enabled" {
			changes = append(changes, Change{
				Repo: repoID, Control: "dependabot_security_updates", Current: state.DependabotSecurityUpdates, Desired: "enabled",
				Action: "enable automated security fixes", Risk: RiskSafe, Impact: "Dependabot opens PRs for vulnerable deps, gated by the same ruleset",
				Kind: KindEnableAutomatedSecurityFixes,
			})
		}
		if !state.DependabotConfigPresent {
			changes = append(changes, Change{
				Repo: repoID, Control: "dependabot_config", Current: "absent", Desired: "present",
				Action: "create .github/dependabot.yml", Risk: RiskSafe, Impact: "scheduled update PRs",
				Kind: KindInstallDependabotConfig, Params: map[string]any{"language": state.PrimaryLanguage},
			})
		}
	}

	// --- Native secret scanning / push protection (public repos: free) ---
	if pol.Security.GitHubSecretScanning && state.Visibility == "public" {
		if state.SecretScanning != ghapi.StatusEnabled {
			findings = append(findings, Finding{Repo: repoID, Control: "secret_scanning", Severity: SeverityHigh, Message: "native secret scanning is disabled"})
			changes = append(changes, Change{
				Repo: repoID, Control: "secret_scanning", Current: "disabled", Desired: "enabled",
				Action: "enable secret scanning", Risk: RiskSafe, Impact: "free for public repos, alert-only",
				Kind: KindEnableSecretScanning,
			})
		}
		if pol.Security.GitHubPushProtection && state.SecretScanningPushProtection != ghapi.StatusEnabled {
			findings = append(findings, Finding{Repo: repoID, Control: "push_protection", Severity: SeverityHigh, Message: "push protection is disabled"})
			changes = append(changes, Change{
				Repo: repoID, Control: "push_protection", Current: "disabled", Desired: "enabled",
				Action: "enable push protection", Risk: RiskSafe, Impact: "blocks pushes containing detected secret patterns",
				Kind: KindEnableSecretScanningPushProt,
			})
		}
		if state.SecretScanningValidityChecks != ghapi.StatusEnabled {
			changes = append(changes, Change{
				Repo: repoID, Control: "secret_scanning_validity_checks", Current: "disabled", Desired: "enabled",
				Action: "enable secret scanning validity checks", Risk: RiskSafe, Impact: "improves signal quality, no new blocking",
				Kind: KindEnableSecretScanningValidity,
			})
		}
	}

	// --- CodeQL ---
	if pol.Security.CodeQL.Enabled != "never" && !state.CodeScanningConfigured {
		codeqlLang, eligible := codeQLLanguageIDs[state.PrimaryLanguage]
		allowedByVisibility := state.Visibility == "public" || pol.Security.CodeQL.PrivateRepos
		if eligible && allowedByVisibility {
			changes = append(changes, Change{
				Repo: repoID, Control: "codeql", Current: "absent", Desired: "default setup, language=" + codeqlLang,
				Action: "enable CodeQL default setup", Risk: RiskSafe,
				Impact: "free on public repos; adds a required check once wired into the ruleset",
				Kind:   KindEnableCodeQL, Params: map[string]any{"language": codeqlLang},
			})
		} else if eligible && !allowedByVisibility {
			findings = append(findings, Finding{
				Repo: repoID, Control: "codeql", Severity: SeverityInfo,
				Message: "CodeQL-eligible but repo is private and security.codeql.private_repos is false — not auto-enabled to avoid unexpected Advanced Security billing",
			})
		}
	}

	return findings, changes
}

// bypassActorFindings flags any bypass actor present on the live ruleset
// that policy did not approve. This is the "bypass actor added" drift
// signal called out explicitly in the threat model — an unapproved bypass
// actor is one of the more dangerous forms of silent policy weakening,
// since it doesn't touch the rule list at all, only who's exempt from it.
func bypassActorFindings(repoID string, live []ghapi.BypassActor, approved []config.BypassActor) []Finding {
	approvedIDs := map[int64]bool{}
	for _, a := range approved {
		if id, ok := roleActorIDs[a.Role]; ok {
			approvedIDs[id] = true
		}
	}
	var findings []Finding
	for _, actor := range live {
		if actor.ActorType == "RepositoryRole" && approvedIDs[actor.ActorID] {
			continue
		}
		findings = append(findings, Finding{
			Repo: repoID, Control: "bypass_actors", Severity: SeverityCritical,
			Message: fmt.Sprintf("unapproved bypass actor on trunk ruleset: type=%s id=%d mode=%s", actor.ActorType, actor.ActorID, actor.Mode),
		})
	}
	return findings
}

func rulesetChange(repoID, branch, current, desiredEnforcement string, reviewCount int, pol *config.Policy, risk Risk) Change {
	return Change{
		Repo: repoID, Control: "ruleset",
		Current: current, Desired: desiredEnforcement,
		Action: fmt.Sprintf("create/update ruleset %q on %s", rulesetName, branch),
		Risk:   risk,
		Impact: "governs PR requirement, signed commits, force-push/delete, required checks, linear history on the trunk branch",
		Kind:   KindCreateOrUpdateRuleset,
		Params: map[string]any{
			"name":                            rulesetName,
			"branch":                          branch,
			"enforcement":                     desiredEnforcement,
			"required_approving_reviews":      reviewCount,
			"require_signed_commits":          pol.DefaultBranch.RequireSignedCommits,
			"block_force_push":                pol.DefaultBranch.BlockForcePush,
			"block_deletion":                  pol.DefaultBranch.BlockDeletion,
			"require_linear_history":          pol.DefaultBranch.RequireLinearHistory,
			"require_conversation_resolution": pol.DefaultBranch.RequireConversationResolution,
			"required_status_checks":          pol.DefaultBranch.RequiredStatusCheckContexts,
			"bypass_actors":                   pol.DefaultBranch.BypassActors,
		},
	}
}

func containsGoTest(content string) bool {
	return strings.Contains(content, "go test") || strings.Contains(content, "go build")
}
