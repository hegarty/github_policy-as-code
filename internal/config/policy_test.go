package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hegarty/github_policy-as-code/internal/config"
)

func TestDefault_IsValid(t *testing.T) {
	if err := config.Default().Validate(); err != nil {
		t.Errorf("built-in default policy should validate cleanly, got: %v", err)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
trunk:
  branch: main
  require_as_default: true
default_branch:
  require_pull_request: true
  enforcement: evaluate
security:
  trufflehog:
    enabled: true
    scan_mode: diff
`), 0o644); err != nil {
		t.Fatal(err)
	}

	pol, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pol.Trunk.Branch != "main" {
		t.Errorf("expected trunk.branch=main, got %q", pol.Trunk.Branch)
	}
}

func TestLoad_RejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-policy.yaml")
	os.WriteFile(path, []byte("version: 2\ntrunk:\n  branch: main\n"), 0o644)

	if _, err := config.Load(path); err == nil {
		t.Error("expected an error for an unsupported policy version")
	}
}

func TestLoad_RejectsMissingTrunkBranch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-policy.yaml")
	os.WriteFile(path, []byte("version: 1\n"), 0o644)

	if _, err := config.Load(path); err == nil {
		t.Error("expected an error when trunk.branch is unset")
	}
}

func TestLoad_RejectsInvalidEnforcement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-policy.yaml")
	os.WriteFile(path, []byte("version: 1\ntrunk:\n  branch: main\ndefault_branch:\n  enforcement: yolo\n"), 0o644)

	if _, err := config.Load(path); err == nil {
		t.Error("expected an error for an invalid enforcement value")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Error("expected an error for a missing policy file")
	}
}
