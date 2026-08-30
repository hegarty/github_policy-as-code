// Package trufflehog implements TruffleHog-specific policy checks. TruffleHog
// is treated as a first-class policy control, not a workflow file the
// controller ignores once installed: this package audits whether the
// installed workflow still matches policy intent, not just whether a file
// with the right name exists.
package trufflehog

import (
	"regexp"
	"strings"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
)

const WorkflowPath = ".github/workflows/trufflehog.yml"

type State struct {
	Installed               bool
	TriggersOnPROpen        bool
	TriggersOnPRSync        bool
	TriggersOnPRReopen      bool
	PinnedToSHA             bool
	UsesMutableRef          bool
	HasExclusions           bool
	FailsOnVerified         bool
	FailsOnUnverified       bool
	MinimalTokenPermissions bool
}

var shaRefPattern = regexp.MustCompile(`trufflesecurity/trufflehog@([0-9a-f]{40})\b`)
var mutableRefPattern = regexp.MustCompile(`trufflesecurity/trufflehog@(main|master|v[0-9]+(\.[0-9]+)*)\b`)

// Inspect examines the repo's workflow files and returns the observed
// TruffleHog configuration state. Returns Installed=false if no TruffleHog
// workflow is present.
func Inspect(workflows []ghapi.WorkflowFile) State {
	var s State
	for _, wf := range workflows {
		if !strings.Contains(wf.Content, "trufflesecurity/trufflehog") {
			continue
		}
		s.Installed = true

		if strings.Contains(wf.Content, "opened") {
			s.TriggersOnPROpen = true
		}
		if strings.Contains(wf.Content, "synchronize") {
			s.TriggersOnPRSync = true
		}
		if strings.Contains(wf.Content, "reopened") {
			s.TriggersOnPRReopen = true
		}

		if shaRefPattern.MatchString(wf.Content) {
			s.PinnedToSHA = true
		}
		if mutableRefPattern.MatchString(wf.Content) {
			s.UsesMutableRef = true
		}

		if strings.Contains(wf.Content, "exclude") || strings.Contains(wf.Content, "--exclude") {
			s.HasExclusions = true
		}

		if strings.Contains(wf.Content, "results=verified") || strings.Contains(wf.Content, "--fail") {
			s.FailsOnVerified = true
		}
		if strings.Contains(wf.Content, "results=verified,unknown") || strings.Contains(wf.Content, "results=unverified") {
			s.FailsOnUnverified = true
		}

		if strings.Contains(wf.Content, "permissions:") && strings.Contains(wf.Content, "contents: read") {
			s.MinimalTokenPermissions = true
		}

		break
	}
	return s
}

// Finding describes a single TruffleHog policy deviation.
type Finding struct {
	Message  string
	Severity string
}

// Evaluate compares observed State against policy intent and returns
// findings. requiredCheck reports whether "trufflehog" appears among the
// repo's required status checks (ruleset or branch protection) — that
// linkage lives outside this package since it's repo-level, not
// TruffleHog-specific.
func Evaluate(s State, requiredCheck, failOnVerified, failOnUnverified bool) []Finding {
	var findings []Finding

	if !s.Installed {
		findings = append(findings, Finding{Severity: "HIGH", Message: "TruffleHog workflow is not installed"})
		return findings
	}
	if !s.TriggersOnPROpen || !s.TriggersOnPRSync || !s.TriggersOnPRReopen {
		findings = append(findings, Finding{Severity: "HIGH", Message: "TruffleHog does not trigger on all of opened/synchronize/reopened — new or updated PR commits may go unscanned"})
	}
	if s.UsesMutableRef {
		findings = append(findings, Finding{Severity: "HIGH", Message: "TruffleHog action referenced by a mutable ref (branch/tag) instead of a pinned commit SHA"})
	}
	if !s.PinnedToSHA {
		findings = append(findings, Finding{Severity: "MEDIUM", Message: "TruffleHog action is not pinned to an immutable commit SHA"})
	}
	if !requiredCheck {
		findings = append(findings, Finding{Severity: "HIGH", Message: "TruffleHog is installed but its status check is not required on the trunk branch — findings can be merged past"})
	}
	if failOnVerified && !s.FailsOnVerified {
		findings = append(findings, Finding{Severity: "CRITICAL", Message: "TruffleHog is configured but does not fail the job on verified (live) secrets — policy requires fail_on_verified_secret"})
	}
	if failOnUnverified && !s.FailsOnUnverified {
		findings = append(findings, Finding{Severity: "MEDIUM", Message: "TruffleHog does not fail on unverified secrets, but policy requires fail_on_unverified_secret"})
	}
	if s.HasExclusions {
		findings = append(findings, Finding{Severity: "MEDIUM", Message: "TruffleHog workflow contains exclusion patterns — verify they are not masking real findings"})
	}
	if !s.MinimalTokenPermissions {
		findings = append(findings, Finding{Severity: "LOW", Message: "TruffleHog workflow does not explicitly declare minimal (contents: read) GITHUB_TOKEN permissions"})
	}
	return findings
}
