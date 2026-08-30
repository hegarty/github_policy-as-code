// Package policy contains the pure, provider-independent policy evaluation
// engine: RepoState + Policy in, Findings and proposed Changes out. Nothing
// in this package makes network calls, which keeps it fully unit-testable
// against fixtures.
package policy

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Risk string

const (
	RiskSafe      Risk = "SAFE"
	RiskSensitive Risk = "SECURITY-SENSITIVE"
	RiskHigh      Risk = "HIGH-RISK"
)

type Finding struct {
	Repo     string   `json:"repo"`
	Control  string   `json:"control"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Change is a single proposed mutation. Kind is the dispatch key the apply
// package switches on; Params carries whatever that operation needs,
// serializable to plan.json.
type Change struct {
	Repo    string         `json:"repo"`
	Control string         `json:"control"`
	Current string         `json:"current"`
	Desired string         `json:"desired"`
	Action  string         `json:"action"`
	Risk    Risk           `json:"risk"`
	Impact  string         `json:"impact"`
	Kind    string         `json:"kind"`
	Params  map[string]any `json:"params,omitempty"`
}

const (
	KindSetDefaultWorkflowPermissions = "set_default_workflow_permissions"
	KindCreateOrUpdateRuleset         = "create_or_update_ruleset"
	KindInstallTruffleHogWorkflow     = "install_trufflehog_workflow"
	KindInstallTruffleHogOnboarding   = "install_trufflehog_full_history_workflow"
	KindInstallCIWorkflow             = "install_ci_workflow"
	KindEnableVulnerabilityAlerts     = "enable_vulnerability_alerts"
	KindEnableAutomatedSecurityFixes  = "enable_automated_security_fixes"
	KindEnableSecretScanningValidity  = "enable_secret_scanning_validity_checks"
	KindEnableSecretScanning          = "enable_secret_scanning"
	KindEnableSecretScanningPushProt  = "enable_secret_scanning_push_protection"
	KindEnableCodeQL                  = "enable_codeql_default_setup"
	KindInstallDependabotConfig       = "install_dependabot_config"
)
