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
	if len(cfg.ClickHouse.Addresses) == 0 {
		t.Error("expected at least one ClickHouse address")
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
clickhouse:
  addresses: ["clickhouse.internal:9000"]
  database: "shinkai_test"
  username: "shinkai"
  password: "secret"
  secure: true
  dial_timeout: "3s"
  retention_days: 45
http:
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
	if len(cfg.ClickHouse.Addresses) != 1 || cfg.ClickHouse.Addresses[0] != "clickhouse.internal:9000" {
		t.Errorf("unexpected ClickHouse addresses: %v", cfg.ClickHouse.Addresses)
	}
	if cfg.ClickHouse.Database != "shinkai_test" || cfg.ClickHouse.RetentionDays != 45 {
		t.Errorf("unexpected ClickHouse config: %+v", cfg.ClickHouse)
	}
}

func TestValidateRejectsInvalidClickHouseConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no addresses", func(cfg *Config) { cfg.ClickHouse.Addresses = nil }},
		{"empty address", func(cfg *Config) { cfg.ClickHouse.Addresses = []string{""} }},
		{"multiple addresses", func(cfg *Config) { cfg.ClickHouse.Addresses = []string{"one:9000", "two:9000"} }},
		{"empty database", func(cfg *Config) { cfg.ClickHouse.Database = "" }},
		{"zero timeout", func(cfg *Config) { cfg.ClickHouse.DialTimeout = 0 }},
		{"zero retention", func(cfg *Config) { cfg.ClickHouse.RetentionDays = 0 }},
		{"HTTP URL", func(cfg *Config) { cfg.HTTP.Endpoint = "http://127.0.0.1:9090" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(cfg)
			if err := validate(cfg); err == nil {
				t.Fatal("validate() unexpectedly succeeded")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}
