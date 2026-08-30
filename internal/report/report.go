// Package report renders findings and changes as human-readable tables or
// machine-readable JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hegarty/github_policy-as-code/internal/policy"
)

// ExitCode maps the most severe finding across a set to the process exit
// code convention: 0 compliant, 1 info, 2 security violation, 3 critical.
func ExitCode(findings []policy.Finding) int {
	code := 0
	for _, f := range findings {
		switch f.Severity {
		case policy.SeverityCritical:
			if code < 3 {
				code = 3
			}
		case policy.SeverityHigh, policy.SeverityMedium:
			if code < 2 {
				code = 2
			}
		case policy.SeverityLow, policy.SeverityInfo:
			if code < 1 {
				code = 1
			}
		}
	}
	return code
}

func WriteFindingsTable(w io.Writer, findings []policy.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	fmt.Fprintf(w, "%-30s %-28s %-9s %s\n", "REPO", "CONTROL", "SEVERITY", "MESSAGE")
	for _, f := range findings {
		fmt.Fprintf(w, "%-30s %-28s %-9s %s\n", truncate(f.Repo, 30), truncate(f.Control, 28), f.Severity, f.Message)
	}
}

func WriteChangesTable(w io.Writer, changes []policy.Change) {
	if len(changes) == 0 {
		fmt.Fprintln(w, "No proposed changes.")
		return
	}
	fmt.Fprintf(w, "%-30s %-16s %-16s %-40s %-18s\n", "REPOSITORY", "CURRENT", "DESIRED", "ACTION", "RISK")
	for _, c := range changes {
		fmt.Fprintf(w, "%-30s %-16s %-16s %-40s %-18s\n",
			truncate(c.Repo, 30), truncate(c.Current, 16), truncate(c.Desired, 16), truncate(c.Action, 40), c.Risk)
	}
}

func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// SeverityCounts summarizes a finding set for a compliance report header.
func SeverityCounts(findings []policy.Finding) map[policy.Severity]int {
	counts := map[policy.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func SummaryLine(findings []policy.Finding) string {
	counts := SeverityCounts(findings)
	var parts []string
	for _, sev := range []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow, policy.SeverityInfo} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		return "compliant — no findings"
	}
	return strings.Join(parts, ", ")
}
