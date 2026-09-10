// Command github-security-controller is a policy-as-code GitHub security
// controller: audit is read-only, plan is read-only, apply executes a
// previously-generated plan, verify re-audits after apply.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hegarty/github_policy-as-code/internal/apply"
	"github.com/hegarty/github_policy-as-code/internal/audit"
	"github.com/hegarty/github_policy-as-code/internal/config"
	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/plan"
	"github.com/hegarty/github_policy-as-code/internal/policy"
	"github.com/hegarty/github_policy-as-code/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(4)
	}
	ctx := context.Background()

	var err error
	var code int
	switch os.Args[1] {
	case "audit":
		code, err = cmdAudit(ctx, os.Args[2:])
	case "plan":
		code, err = cmdPlan(ctx, os.Args[2:])
	case "apply":
		code, err = cmdApply(ctx, os.Args[2:])
	case "verify":
		code, err = cmdVerify(ctx, os.Args[2:])
	case "repo":
		if len(os.Args) < 3 || os.Args[2] != "create" {
			usage()
			os.Exit(4)
		}
		code, err = cmdRepoCreate(ctx, os.Args[3:])
	default:
		usage()
		os.Exit(4)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if code == 0 {
			code = 4
		}
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, `github-security-controller — GitHub repository security policy controller

Usage:
  github-security-controller audit --owner OWNER [--policy FILE] [--json]
  github-security-controller audit --repo OWNER/NAME [--policy FILE] [--json]
  github-security-controller plan --owner OWNER [--policy FILE] --out plan.json
  github-security-controller apply --plan plan.json
  github-security-controller verify --owner OWNER [--policy FILE]
  github-security-controller repo create --owner OWNER --name NAME --visibility public

audit and plan are strictly read-only. apply is the only command that
mutates GitHub state, and only for the exact changes recorded in the plan
file it's given.`)
}

func newClient() (ghapi.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		var err error
		token, err = ghapi.TokenFromGHCLI()
		if err != nil {
			return nil, fmt.Errorf("no GITHUB_TOKEN set and could not resolve a token from gh CLI: %w", err)
		}
	}
	return ghapi.NewClient(token), nil
}

func loadPolicy(path string) (*config.Policy, error) {
	if path == "" {
		return config.Default(), nil
	}
	return config.Load(path)
}

type target struct {
	Owner, Repo string
}

func resolveTargets(ctx context.Context, c ghapi.Client, owner, repoFlag string) ([]target, error) {
	if repoFlag != "" {
		parts := strings.SplitN(repoFlag, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("--repo must be in OWNER/NAME form, got %q", repoFlag)
		}
		return []target{{Owner: parts[0], Repo: parts[1]}}, nil
	}
	if owner == "" {
		return nil, fmt.Errorf("either --owner or --repo is required")
	}
	ownerType, err := c.GetOwnerType(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("resolving owner %q: %w", owner, err)
	}
	repos, err := c.ListRepoNames(ctx, owner, ownerType)
	if err != nil {
		return nil, fmt.Errorf("listing repos for %q: %w", owner, err)
	}
	var targets []target
	for _, r := range repos {
		if r.Archived || r.Fork {
			continue
		}
		targets = append(targets, target{Owner: owner, Repo: r.Name})
	}
	return targets, nil
}

func cmdAudit(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	owner := fs.String("owner", "", "GitHub owner (user or org) to audit all non-archived, non-fork repos for")
	repoFlag := fs.String("repo", "", "single OWNER/NAME repo to audit instead of --owner")
	policyPath := fs.String("policy", "", "path to security-policy.yaml (defaults to built-in baseline policy)")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	fs.Parse(args)

	c, err := newClient()
	if err != nil {
		return 4, err
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return 4, err
	}
	targets, err := resolveTargets(ctx, c, *owner, *repoFlag)
	if err != nil {
		return 4, err
	}

	var allFindings []policy.Finding
	for _, t := range targets {
		state, err := audit.Collect(ctx, c, t.Owner, t.Repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s/%s: %v\n", t.Owner, t.Repo, err)
			continue
		}
		findings, _ := policy.Evaluate(state, pol)
		allFindings = append(allFindings, findings...)
	}

	if *asJSON {
		if err := report.WriteJSON(os.Stdout, allFindings); err != nil {
			return 4, err
		}
	} else {
		report.WriteFindingsTable(os.Stdout, allFindings)
		fmt.Println()
		fmt.Println("Summary:", report.SummaryLine(allFindings))
	}
	return report.ExitCode(allFindings), nil
}

func cmdPlan(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	owner := fs.String("owner", "", "GitHub owner (user or org) to plan for")
	repoFlag := fs.String("repo", "", "single OWNER/NAME repo to plan for instead of --owner")
	policyPath := fs.String("policy", "", "path to security-policy.yaml (defaults to built-in baseline policy)")
	out := fs.String("out", "plan.json", "output path for the plan artifact")
	fs.Parse(args)

	c, err := newClient()
	if err != nil {
		return 4, err
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return 4, err
	}
	targets, err := resolveTargets(ctx, c, *owner, *repoFlag)
	if err != nil {
		return 4, err
	}

	pins, err := workflowPins(ctx, c)
	if err != nil {
		return 4, fmt.Errorf("resolving pinned Action SHAs: %w", err)
	}

	var repoPlans []plan.RepoPlan
	for _, t := range targets {
		state, err := audit.Collect(ctx, c, t.Owner, t.Repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s/%s: %v\n", t.Owner, t.Repo, err)
			continue
		}
		findings, changes := policy.Evaluate(state, pol)
		injectPins(changes, pins, state.DefaultBranch)

		hash, err := plan.HashState(state.ForHashing())
		if err != nil {
			return 4, err
		}
		repoPlans = append(repoPlans, plan.RepoPlan{
			Owner: t.Owner, Repo: t.Repo, StateHash: hash,
			Findings: findings, Changes: changes,
		})
	}

	policyHash := "builtin-default"
	if *policyPath != "" {
		data, err := os.ReadFile(*policyPath)
		if err != nil {
			return 4, err
		}
		policyHash = plan.HashPolicyBytes(data)
	}

	p := plan.New(*policyPath, policyHash, repoPlans)
	if err := p.Save(*out); err != nil {
		return 4, err
	}

	var allFindings []policy.Finding
	var allChanges []policy.Change
	for _, rp := range p.Repos {
		allFindings = append(allFindings, rp.Findings...)
		allChanges = append(allChanges, rp.Changes...)
	}
	fmt.Println("Findings:")
	report.WriteFindingsTable(os.Stdout, allFindings)
	fmt.Println()
	fmt.Println("Proposed changes:")
	report.WriteChangesTable(os.Stdout, allChanges)
	fmt.Println()
	fmt.Printf("Plan written to %s (fingerprint %s)\n", *out, p.Fingerprint[:12])
	return 0, nil
}

func cmdApply(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	planPath := fs.String("plan", "plan.json", "path to a plan.json produced by 'plan'")
	force := fs.Bool("force", false, "apply even if the plan appears stale (dangerous)")
	fs.Parse(args)

	p, err := plan.Load(*planPath)
	if err != nil {
		return 4, err
	}
	c, err := newClient()
	if err != nil {
		return 4, err
	}

	currentHashes := map[string]string{}
	for _, rp := range p.Repos {
		state, err := audit.Collect(ctx, c, rp.Owner, rp.Repo)
		if err != nil {
			return 4, fmt.Errorf("re-checking %s/%s before apply: %w", rp.Owner, rp.Repo, err)
		}
		hash, err := plan.HashState(state.ForHashing())
		if err != nil {
			return 4, err
		}
		currentHashes[rp.Owner+"/"+rp.Repo] = hash
	}
	if err := p.CheckFresh(currentHashes); err != nil {
		if !*force {
			return 3, err
		}
		fmt.Fprintln(os.Stderr, "warning: applying a stale plan with --force:", err)
	}

	failed := false
	for _, rp := range p.Repos {
		if len(rp.Changes) == 0 {
			continue
		}
		fmt.Printf("Applying %d change(s) to %s/%s...\n", len(rp.Changes), rp.Owner, rp.Repo)
		results := apply.Apply(ctx, c, rp.Owner, rp.Repo, rp.Changes)
		for _, res := range results {
			if res.Err != nil {
				failed = true
				fmt.Printf("  FAILED: %s — %v\n", res.Change.Action, res.Err)
			} else {
				fmt.Printf("  OK: %s\n", res.Change.Action)
			}
		}
	}
	if failed {
		return 4, fmt.Errorf("one or more changes failed to apply")
	}
	return 0, nil
}

func cmdVerify(ctx context.Context, args []string) (int, error) {
	// verify is audit run again post-apply; same read-only semantics.
	return cmdAudit(ctx, args)
}

func cmdRepoCreate(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("repo create", flag.ExitOnError)
	owner := fs.String("owner", "", "owner (user or org) to create the repo under")
	name := fs.String("name", "", "repository name")
	visibility := fs.String("visibility", "public", "public or private")
	fs.Parse(args)

	if *owner == "" || *name == "" {
		return 4, fmt.Errorf("--owner and --name are required")
	}
	c, err := newClient()
	if err != nil {
		return 4, err
	}
	ownerType, err := c.GetOwnerType(ctx, *owner)
	if err != nil {
		return 4, err
	}
	if err := c.CreateRepo(ctx, *owner, ownerType, *name, *visibility); err != nil {
		return 4, err
	}
	fmt.Printf("Created %s/%s (%s). It has no commits yet — push an initial commit to %q,\n", *owner, *name, *visibility, "main")
	fmt.Println("then run 'plan --repo " + *owner + "/" + *name + "' and 'apply' to install baseline security controls.")
	return 0, nil
}
