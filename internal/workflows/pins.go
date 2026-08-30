package workflows

import (
	"context"
	"fmt"

	"github.com/hegarty/github_policy-as-code/internal/ghapi"
)

// Pins holds resolved immutable commit SHAs for every third-party (or
// first-party) Action the controller's rendered workflows reference. All
// SHAs are resolved once at plan time, not at apply time, so the plan
// artifact records exactly what will be installed.
type Pins struct {
	CheckoutSHA   string
	SetupGoSHA    string
	TruffleHogSHA string
}

const (
	checkoutRef   = "v4"
	setupGoRef    = "v5"
	trufflehogRef = "main"
)

func ResolvePins(ctx context.Context, c ghapi.Client) (Pins, error) {
	var p Pins
	var err error

	if p.CheckoutSHA, err = c.ResolveRef(ctx, "actions", "checkout", checkoutRef); err != nil {
		return p, fmt.Errorf("resolving actions/checkout@%s: %w", checkoutRef, err)
	}
	if p.SetupGoSHA, err = c.ResolveRef(ctx, "actions", "setup-go", setupGoRef); err != nil {
		return p, fmt.Errorf("resolving actions/setup-go@%s: %w", setupGoRef, err)
	}
	if p.TruffleHogSHA, err = c.ResolveRef(ctx, "trufflesecurity", "trufflehog", trufflehogRef); err != nil {
		return p, fmt.Errorf("resolving trufflesecurity/trufflehog@%s: %w", trufflehogRef, err)
	}
	return p, nil
}
