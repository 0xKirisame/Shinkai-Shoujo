package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for shinkai-shoujo.
type Config struct {
	OTel        OTelConfig        `mapstructure:"otel"`
	AWS         AWSConfig         `mapstructure:"aws"`
	Observation ObservationConfig `mapstructure:"observation"`
	Storage     StorageConfig     `mapstructure:"storage"`
	Metrics     MetricsConfig     `mapstructure:"metrics"`
}

type OTelConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

type AWSConfig struct {
	Region string `mapstructure:"region"`
}

type ObservationConfig struct {
	WindowDays        int `mapstructure:"window_days"`
	MinObservationDay int `mapstructure:"min_observation_days"`
}

type StorageConfig struct {
	Path string `mapstructure:"path"`
}

type MetricsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
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
	home, _ := os.UserHomeDir()
	storagePath := filepath.Join(home, ".shinkai-shoujo", "data.db")
	return &Config{
		OTel: OTelConfig{
			Endpoint: "0.0.0.0:4318",
		},
		AWS: AWSConfig{
			Region: "us-east-1",
		},
		Observation: ObservationConfig{
			WindowDays:        30,
			MinObservationDay: 7,
		},
		Storage: StorageConfig{
			Path: storagePath,
		},
		Metrics: MetricsConfig{
			Endpoint: "0.0.0.0:9090",
		},
	}
}

// Load reads configuration from the given path using viper.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	def := DefaultConfig()
	v.SetDefault("otel.endpoint", def.OTel.Endpoint)
	v.SetDefault("aws.region", def.AWS.Region)
	v.SetDefault("observation.window_days", def.Observation.WindowDays)
	v.SetDefault("observation.min_observation_days", def.Observation.MinObservationDay)
	v.SetDefault("storage.path", def.Storage.Path)
	v.SetDefault("metrics.endpoint", def.Metrics.Endpoint)

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

	cfg.Storage.Path = ExpandPath(cfg.Storage.Path)
	return &cfg, nil
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
