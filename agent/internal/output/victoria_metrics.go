package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/binhbl/edr-threat-hunting/agent/internal/correlation"
	"github.com/binhbl/edr-threat-hunting/agent/internal/scoring"
	log "github.com/sirupsen/logrus"
)

// VictoriaMetricsExporter sends threat alerts to VictoriaMetrics
type VictoriaMetricsExporter struct {
	endpoint   string
	httpClient *http.Client
	enabled    bool
}

// NewVictoriaMetricsExporter creates a new VictoriaMetrics exporter
func NewVictoriaMetricsExporter(endpoint string, enabled bool) *VictoriaMetricsExporter {
	return &VictoriaMetricsExporter{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		enabled: enabled,
	}
}

// ThreatAlert represents a structured threat alert
type ThreatAlert struct {
	Timestamp           time.Time              `json:"timestamp"`
	Hostname            string                 `json:"hostname"`
	ThreatScore         float32                `json:"threat_score"`
	Severity            string                 `json:"severity"`
	AttackChainSummary  string                 `json:"attack_chain_summary"`
	ProcessChain        []string               `json:"process_chain"`
	MitreTactics        []string               `json:"mitre_tactics"`
	MitreTechniques     []string               `json:"mitre_techniques"`
	BehavioralContext   map[string]interface{} `json:"behavioral_context"`
	RecommendedAction   string                 `json:"recommended_action"`

	// Scoring breakdown
	RarityScore         float32                `json:"rarity_score"`
	SequenceScore       float32                `json:"sequence_score"`
	MLScore             float32                `json:"ml_score"`
}

// SendThreat sends a threat alert to VictoriaMetrics
func (vm *VictoriaMetricsExporter) SendThreat(threat scoring.Threat, chain correlation.AttackChain, hostname string) error {
	if !vm.enabled {
		return nil
	}

	// Build process chain string array
	processChain := make([]string, len(chain.ProcessChain))
	for i, proc := range chain.ProcessChain {
		processChain[i] = fmt.Sprintf("%s (PID:%d)", proc.ProcessName, proc.PID)
	}

	alert := ThreatAlert{
		Timestamp:          threat.Timestamp,
		Hostname:           hostname,
		ThreatScore:        threat.Score,
		Severity:           threat.Severity,
		AttackChainSummary: threat.AttackChainSummary,
		ProcessChain:       processChain,
		MitreTactics:       threat.MitreTactics,
		MitreTechniques:    threat.MitreTechniques,
		BehavioralContext:  threat.Context,
		RecommendedAction:  threat.RecommendedAction,
		RarityScore:        threat.RarityScore,
		SequenceScore:      threat.SequenceScore,
		MLScore:            threat.MLScore,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	// Send to VictoriaMetrics via JSON API
	req, err := http.NewRequest("POST", vm.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := vm.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("victoria metrics returned status %d", resp.StatusCode)
	}

	log.WithFields(log.Fields{
		"hostname":     hostname,
		"threat_score": threat.Score,
		"severity":     threat.Severity,
	}).Debug("Threat alert sent to VictoriaMetrics")

	return nil
}

// SendBatch sends multiple threat alerts in a single batch
func (vm *VictoriaMetricsExporter) SendBatch(alerts []ThreatAlert) error {
	if !vm.enabled || len(alerts) == 0 {
		return nil
	}

	jsonData, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("failed to marshal alerts: %w", err)
	}

	req, err := http.NewRequest("POST", vm.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := vm.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("victoria metrics returned status %d", resp.StatusCode)
	}

	log.WithField("batch_size", len(alerts)).Debug("Batch threat alerts sent to VictoriaMetrics")

	return nil
}
