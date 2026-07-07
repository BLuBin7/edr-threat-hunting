package config

import (
	"fmt"
	"os"
	"time"

	"github.com/binhbl/edr-threat-hunting/agent/internal/monitors"
	"github.com/spf13/viper"
)

type Config struct {
	Agent       AgentConfig       `yaml:"agent"`
	Monitors    MonitorsConfig    `yaml:"monitors"`
	Correlation CorrelationConfig `yaml:"correlation"`
	Scoring     ScoringConfig     `yaml:"scoring"`
	ML          MLConfig          `yaml:"ml"`
	Rules       RulesConfig       `yaml:"rules"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Output      OutputConfig      `yaml:"output"`
}

type AgentConfig struct {
	Hostname    string `yaml:"hostname"`
	NodeName    string `yaml:"node_name"`
	Environment string `yaml:"environment"`
}

type MonitorsConfig struct {
	Process     monitors.ProcessMonitorConfig     `yaml:"process"`
	File        monitors.FileMonitorConfig        `yaml:"file"`
	Network     monitors.NetworkMonitorConfig     `yaml:"network"`
	Persistence monitors.PersistenceMonitorConfig `yaml:"persistence"`
}

type CorrelationConfig struct {
	WindowSize  time.Duration `yaml:"window_size"`
	MaxMemoryMB int64         `yaml:"max_memory_mb"`
}

type ScoringConfig struct {
	RarityWeight   float32 `yaml:"rarity_weight"`
	SequenceWeight float32 `yaml:"sequence_weight"`
	MLWeight       float32 `yaml:"ml_weight"`
	Threshold      float32 `yaml:"threshold"`
}

type MLConfig struct {
	ModelPath        string `yaml:"model_path"`
	EnableInference  bool   `yaml:"enable_inference"`
	FallbackOnError  bool   `yaml:"fallback_on_error"`
}

type RulesConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RulesDir  string `yaml:"rules_dir"`
	AutoReload bool  `yaml:"auto_reload"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type OutputConfig struct {
	VictoriaMetrics VictoriaMetricsConfig `yaml:"victoria_metrics"`
	LogFile         string                `yaml:"log_file"`
}

type VictoriaMetricsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

func Load(path string) (*Config, error) {
	// Set defaults
	viper.SetDefault("agent.hostname", getHostname())
	viper.SetDefault("agent.node_name", getHostname())
	viper.SetDefault("agent.environment", "production")

	viper.SetDefault("monitors.process.poll_interval", "1s")
	viper.SetDefault("monitors.process.track_lineage", true)

	viper.SetDefault("monitors.file.recursive", true)
	viper.SetDefault("monitors.file.watch_paths", []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/.ssh",
		"/home/*/.ssh",
	})

	viper.SetDefault("monitors.network.poll_interval", "5s")
	viper.SetDefault("monitors.network.track_dns", true)

	viper.SetDefault("monitors.persistence.watch_cron", true)
	viper.SetDefault("monitors.persistence.watch_systemd", true)
	viper.SetDefault("monitors.persistence.watch_autorun", true)

	viper.SetDefault("correlation.window_size", "30m")
	viper.SetDefault("correlation.max_memory_mb", 100)

	viper.SetDefault("scoring.rarity_weight", 0.3)
	viper.SetDefault("scoring.sequence_weight", 0.4)
	viper.SetDefault("scoring.ml_weight", 0.3)
	viper.SetDefault("scoring.threshold", 0.7)

	viper.SetDefault("ml.model_path", "/etc/edr-agent/model.onnx")
	viper.SetDefault("ml.enable_inference", true)
	viper.SetDefault("ml.fallback_on_error", true)

	viper.SetDefault("rules.enabled", true)
	viper.SetDefault("rules.rules_dir", "/etc/edr-agent/rules")
	viper.SetDefault("rules.auto_reload", true)

	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.port", 9090)

	viper.SetDefault("output.victoria_metrics.enabled", false)
	viper.SetDefault("output.victoria_metrics.endpoint", "http://victoria-metrics:8428/api/v1/write")
	viper.SetDefault("output.log_file", "/var/log/edr-agent/agent.log")

	// Load config file
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
			fmt.Printf("Config file not found at %s, using defaults\n", path)
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
