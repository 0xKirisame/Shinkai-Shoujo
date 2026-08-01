package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for shinkai-shoujo.
type Config struct {
	OTel        OTelConfig        `mapstructure:"otel" yaml:"otel"`
	AWS         AWSConfig         `mapstructure:"aws" yaml:"aws"`
	Observation ObservationConfig `mapstructure:"observation" yaml:"observation"`
	ClickHouse  ClickHouseConfig  `mapstructure:"clickhouse" yaml:"clickhouse"`
	HTTP        HTTPConfig        `mapstructure:"http" yaml:"http"`
}

type OTelConfig struct {
	Endpoint      string `mapstructure:"endpoint" yaml:"endpoint"`
	RoleAttribute string `mapstructure:"role_attribute" yaml:"role_attribute"`
	AuthToken     string `mapstructure:"auth_token" yaml:"auth_token"`
}

type AWSConfig struct {
	Region    string `mapstructure:"region" yaml:"region"`
	AccountID string `mapstructure:"account_id" yaml:"account_id,omitempty"`
}

type ObservationConfig struct {
	WindowDays        int `mapstructure:"window_days" yaml:"window_days"`
	MinObservationDay int `mapstructure:"min_observation_days" yaml:"min_observation_days"`
}

type ClickHouseConfig struct {
	Addresses     []string      `mapstructure:"addresses" yaml:"addresses"`
	Database      string        `mapstructure:"database" yaml:"database"`
	Username      string        `mapstructure:"username" yaml:"username"`
	Password      string        `mapstructure:"password" yaml:"password,omitempty"`
	Secure        bool          `mapstructure:"secure" yaml:"secure"`
	DialTimeout   time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout"`
	RetentionDays int           `mapstructure:"retention_days" yaml:"retention_days"`
}

type HTTPConfig struct {
	Endpoint  string `mapstructure:"endpoint" yaml:"endpoint"`
	AuthToken string `mapstructure:"auth_token" yaml:"auth_token,omitempty"`
}

// DefaultConfigPath returns the default path to the config file.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".shinkai-shoujo/config.yaml"
	}
	return filepath.Join(home, ".shinkai-shoujo", "config.yaml")
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		OTel: OTelConfig{
			Endpoint:      "127.0.0.1:4318",
			RoleAttribute: "aws.iam.role.arn",
		},
		AWS: AWSConfig{
			Region: "us-east-1",
		},
		Observation: ObservationConfig{
			WindowDays:        30,
			MinObservationDay: 7,
		},
		ClickHouse: ClickHouseConfig{
			Addresses:     []string{"localhost:9000"},
			Database:      "shinkai_shoujo",
			Username:      "default",
			DialTimeout:   5 * time.Second,
			RetentionDays: 90,
		},
		HTTP: HTTPConfig{
			Endpoint: "127.0.0.1:9090",
		},
	}
}

// Load reads configuration from the given path using viper.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	def := DefaultConfig()
	v.SetDefault("otel.endpoint", def.OTel.Endpoint)
	v.SetDefault("otel.role_attribute", def.OTel.RoleAttribute)
	v.SetDefault("otel.auth_token", def.OTel.AuthToken)
	v.SetDefault("aws.region", def.AWS.Region)
	v.SetDefault("observation.window_days", def.Observation.WindowDays)
	v.SetDefault("observation.min_observation_days", def.Observation.MinObservationDay)
	v.SetDefault("clickhouse.addresses", def.ClickHouse.Addresses)
	v.SetDefault("clickhouse.database", def.ClickHouse.Database)
	v.SetDefault("clickhouse.username", def.ClickHouse.Username)
	v.SetDefault("clickhouse.password", def.ClickHouse.Password)
	v.SetDefault("clickhouse.secure", def.ClickHouse.Secure)
	v.SetDefault("clickhouse.dial_timeout", def.ClickHouse.DialTimeout)
	v.SetDefault("clickhouse.retention_days", def.ClickHouse.RetentionDays)
	v.SetDefault("http.endpoint", def.HTTP.Endpoint)
	v.SetDefault("http.auth_token", def.HTTP.AuthToken)

	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil, fmt.Errorf("config file not found at %s — run 'shinkai-shoujo init' to create one", path)
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Observation.WindowDays <= 0 {
		return fmt.Errorf("observation.window_days must be positive")
	}
	if cfg.Observation.MinObservationDay <= 0 {
		return fmt.Errorf("observation.min_observation_days must be positive")
	}
	if cfg.Observation.MinObservationDay > cfg.Observation.WindowDays {
		return fmt.Errorf("observation.min_observation_days must not exceed observation.window_days")
	}
	if len(cfg.ClickHouse.Addresses) == 0 {
		return fmt.Errorf("clickhouse.addresses must not be empty")
	}
	if len(cfg.ClickHouse.Addresses) != 1 {
		return fmt.Errorf("clickhouse.addresses must contain exactly one address until cluster migrations are supported")
	}
	for _, address := range cfg.ClickHouse.Addresses {
		if strings.TrimSpace(address) == "" {
			return fmt.Errorf("clickhouse.addresses must not contain an empty address")
		}
	}
	if strings.TrimSpace(cfg.ClickHouse.Database) == "" {
		return fmt.Errorf("clickhouse.database must not be empty")
	}
	if cfg.ClickHouse.DialTimeout <= 0 {
		return fmt.Errorf("clickhouse.dial_timeout must be positive")
	}
	if cfg.ClickHouse.RetentionDays <= 0 {
		return fmt.Errorf("clickhouse.retention_days must be positive")
	}
	if strings.TrimSpace(cfg.AWS.Region) == "" {
		return fmt.Errorf("aws.region must not be empty")
	}
	if strings.TrimSpace(cfg.OTel.Endpoint) == "" {
		return fmt.Errorf("otel.endpoint must not be empty")
	}
	if strings.TrimSpace(cfg.HTTP.Endpoint) == "" {
		return fmt.Errorf("http.endpoint must not be empty")
	}
	if strings.Contains(cfg.HTTP.Endpoint, "://") {
		return fmt.Errorf("http.endpoint must be a host:port listen address, not a URL")
	}

	host, err := endpointHost(cfg.OTel.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid otel.endpoint %q: %w", cfg.OTel.Endpoint, err)
	}
	if !isLoopbackHost(host) && strings.TrimSpace(cfg.OTel.AuthToken) == "" {
		return fmt.Errorf("otel.auth_token is required when otel.endpoint binds to non-loopback host %q", host)
	}
	httpHost, err := endpointHost(cfg.HTTP.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid http.endpoint %q: %w", cfg.HTTP.Endpoint, err)
	}
	if !isLoopbackHost(httpHost) && strings.TrimSpace(cfg.HTTP.AuthToken) == "" {
		return fmt.Errorf("http.auth_token is required when http.endpoint binds to non-loopback host %q", httpHost)
	}
	return nil
}

func endpointHost(endpoint string) (string, error) {
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return "", err
		}
		if u.Host == "" {
			return "", fmt.Errorf("missing host")
		}
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	return host, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	if unzoned, _, ok := strings.Cut(host, "%"); ok {
		host = unzoned
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ExpandPath expands ~ in a file path to the user's home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
