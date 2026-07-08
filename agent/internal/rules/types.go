package rules

import "time"

// Rule represents a detection rule loaded from YAML
type Rule struct {
	// Metadata
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Category    string   `yaml:"category" json:"category"`       // execution, credential_access, persistence, etc.
	Severity    string   `yaml:"severity" json:"severity"`       // low, medium, high, critical
	Enabled     bool     `yaml:"enabled" json:"enabled"`         // Runtime enable/disable
	Version     string   `yaml:"version" json:"version"`         // Rule version
	Author      string   `yaml:"author" json:"author"`           // Rule author
	References  []string `yaml:"references" json:"references"`   // External links

	// MITRE ATT&CK mapping
	MITRETactics    []string `yaml:"mitre_tactics" json:"mitre_tactics"`       // TA0001, TA0002, etc.
	MITRETechniques []string `yaml:"mitre_techniques" json:"mitre_techniques"` // T1059.001, etc.

	// Detection logic
	Conditions []Condition `yaml:"conditions" json:"conditions"` // AND logic between conditions

	// Response
	Action         string  `yaml:"action" json:"action"`                   // alert, block, quarantine
	ScoreModifier  float32 `yaml:"score_modifier" json:"score_modifier"`   // Add to threat score (0.0-1.0)

	// Metadata (runtime)
	FilePath     string    `yaml:"-" json:"file_path"`     // Source YAML file
	LoadedAt     time.Time `yaml:"-" json:"loaded_at"`     // When loaded
	LastModified time.Time `yaml:"-" json:"last_modified"` // File mtime
	MatchCount   int64     `yaml:"-" json:"match_count"`   // How many times matched
}

// Condition represents a single detection condition
type Condition struct {
	Field    string      `yaml:"field" json:"field"`       // process.commandline, file.path, etc.
	Operator string      `yaml:"operator" json:"operator"` // contains, equals, regex, gt, lt, in
	Value    interface{} `yaml:"value" json:"value"`       // String, []string, number
	Negate   bool        `yaml:"negate" json:"negate"`     // NOT condition
}

// RuleSet is a collection of rules with metadata
type RuleSet struct {
	Rules       []*Rule
	LoadedAt    time.Time
	RulesDir    string
	TotalRules  int
	EnabledRules int
	Categories  map[string]int // category -> count
}

// MatchResult represents the result of rule evaluation
type MatchResult struct {
	Matched       bool      `json:"matched"`
	Rule          *Rule     `json:"rule"`
	MatchedFields []string  `json:"matched_fields"` // Which fields matched
	Timestamp     time.Time `json:"timestamp"`
	EventID       string    `json:"event_id"` // Reference to event that triggered
}

// SeverityLevel converts string severity to numeric level
func (r *Rule) SeverityLevel() int {
	switch r.Severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// IsValid checks if rule has required fields
func (r *Rule) IsValid() bool {
	if r.Name == "" || r.Category == "" || r.Severity == "" {
		return false
	}
	if len(r.Conditions) == 0 {
		return false
	}
	return true
}
