package main

import (
	"context"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
	"github.com/hegarty/github_policy-as-code/internal/policy"
	"github.com/hegarty/github_policy-as-code/internal/workflows"
)

func workflowPins(ctx context.Context, c ghapi.Client) (workflows.Pins, error) {
	return workflows.ResolvePins(ctx, c)
}

// injectPins fills in the resolved, immutable Action SHAs (and a couple of
// per-repo values not known to the pure policy package) into the Params of
// any Change that installs a workflow file. Kept as a post-processing step
// so internal/policy stays free of network calls.
func injectPins(changes []policy.Change, pins workflows.Pins, defaultBranch string) {
	branch := defaultBranch
	if branch == "" {
		branch = "main"
	}
	for i := range changes {
		if changes[i].Params == nil {
			changes[i].Params = map[string]any{}
		}
		switch changes[i].Kind {
		case policy.KindInstallTruffleHogWorkflow, policy.KindInstallTruffleHogOnboarding:
			changes[i].Params["checkout_sha"] = pins.CheckoutSHA
			changes[i].Params["trufflehog_sha"] = pins.TruffleHogSHA
			changes[i].Params["branch"] = branch
		case policy.KindInstallCIWorkflow:
			changes[i].Params["checkout_sha"] = pins.CheckoutSHA
			changes[i].Params["setup_go_sha"] = pins.SetupGoSHA
			changes[i].Params["branch"] = branch
		case policy.KindInstallDependabotConfig:
			changes[i].Params["branch"] = branch
		}
	}
}
