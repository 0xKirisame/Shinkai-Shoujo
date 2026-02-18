package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OTel.Endpoint == "" {
		t.Error("expected non-empty OTel endpoint")
	}
	if cfg.Observation.WindowDays <= 0 {
		t.Error("expected positive window_days")
	}
	if cfg.Storage.Path == "" {
		t.Error("expected non-empty storage path")
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~/foo/bar", filepath.Join(home, "foo/bar")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		got := ExpandPath(tt.input)
		if got != tt.expected {
			t.Errorf("ExpandPath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `
otel:
  endpoint: "127.0.0.1:4318"
aws:
  region: "eu-west-1"
observation:
  window_days: 14
  min_observation_days: 3
storage:
  path: "/tmp/test.db"
metrics:
  endpoint: "127.0.0.1:9090"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.OTel.Endpoint != "127.0.0.1:4318" {
		t.Errorf("unexpected OTel endpoint: %s", cfg.OTel.Endpoint)
	}
	if cfg.AWS.Region != "eu-west-1" {
		t.Errorf("unexpected region: %s", cfg.AWS.Region)
	}
	if cfg.Observation.WindowDays != 14 {
		t.Errorf("unexpected window_days: %d", cfg.Observation.WindowDays)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}
