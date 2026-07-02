package scoring

import (
	"fmt"
	"strings"
	"time"

	"github.com/binhbl/edr-threat-hunting/agent/internal/correlation"
)

// Engine calculates threat scores from attack chains
type Engine struct {
	rarityWeight   float32
	sequenceWeight float32
	mlWeight       float32
	threshold      float32
}

type EngineOption func(*Engine)

func WithRarityWeight(w float32) EngineOption {
	return func(e *Engine) { e.rarityWeight = w }
}

func WithSequenceWeight(w float32) EngineOption {
	return func(e *Engine) { e.sequenceWeight = w }
}

func WithMLWeight(w float32) EngineOption {
	return func(e *Engine) { e.mlWeight = w }
}

func WithThreshold(t float32) EngineOption {
	return func(e *Engine) { e.threshold = t }
}

func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		rarityWeight:   0.3,
		sequenceWeight: 0.4,
		mlWeight:       0.3,
		threshold:      0.7,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Threat represents a detected threat with context
type Threat struct {
	Score               float32
	Severity            string
	AttackChainSummary  string
	Context             map[string]interface{}
	MitreTactics        []string
	MitreTechniques     []string
	RecommendedAction   string
	Timestamp           time.Time

	// Detailed scoring breakdown
	RarityScore         float32
	SequenceScore       float32
	MLScore             float32
}

// Calculate computes the final threat score
func (e *Engine) Calculate(chain correlation.AttackChain, mlScore float32) Threat {
	// Component 1: Rarity Score
	rarityScore := e.calculateRarityScore(chain)

	// Component 2: Sequence Score
	sequenceScore := e.calculateSequenceScore(chain)

	// Component 3: ML Anomaly Score (from ONNX inference)
	mlAnomalyScore := mlScore

	// Weighted final score
	finalScore := (e.rarityWeight * rarityScore) +
	              (e.sequenceWeight * sequenceScore) +
	              (e.mlWeight * mlAnomalyScore)

	severity := e.getSeverity(finalScore)

	threat := Threat{
		Score:               finalScore,
		Severity:            severity,
		AttackChainSummary:  e.buildChainSummary(chain),
		Context:             e.buildContext(chain),
		MitreTactics:        chain.MitreTactics,
		MitreTechniques:     chain.MitreTechniques,
		RecommendedAction:   e.getRecommendedAction(chain, severity),
		Timestamp:           time.Now(),
		RarityScore:         rarityScore,
		SequenceScore:       sequenceScore,
		MLScore:             mlAnomalyScore,
	}

	return threat
}

func (e *Engine) calculateRarityScore(chain correlation.AttackChain) float32 {
	score := float32(0.0)

	// Rare parent-child process
	if chain.IsRareParentChild {
		score += 0.4
	}

	// High commandline entropy (obfuscated)
	if chain.CmdlineEntropy > 4.5 {
		score += 0.3
	}

	// Encoded commands
	if chain.HasEncodedCmd {
		score += 0.3
	}

	// Privilege escalation
	if chain.HasPrivilegeEscalation {
		score += 0.5
	}

	// Sensitive file access
	if chain.SensitiveFileAccessCount > 0 {
		score += 0.4
	}

	return min(score, 1.0)
}

func (e *Engine) calculateSequenceScore(chain correlation.AttackChain) float32 {
	score := float32(0.0)

	// Long process lineage (deep chain = suspicious)
	if chain.ProcessLineageDepth > 3 {
		score += 0.2 * float32(min(float32(chain.ProcessLineageDepth-3), 3.0))
	}

	// Execution → File → Network pattern (classic attack chain)
	hasExecution := chain.ProcessLineageDepth > 1
	hasFileActivity := chain.FileModificationCount > 0
	hasNetworkActivity := chain.NetworkConnectionCount > 0

	if hasExecution && hasFileActivity && hasNetworkActivity {
		score += 0.6
	} else if (hasExecution && hasFileActivity) || (hasExecution && hasNetworkActivity) {
		score += 0.3
	}

	// Persistence mechanism added
	if chain.HasPersistenceMechanism {
		score += 0.4
	}

	// Mass file activity (ransomware-like)
	if chain.MassFileActivityRate > 100.0 {
		score += 0.5
	}

	// Beaconing detected (C2 communication)
	if chain.BeaconingScore > 0.7 {
		score += 0.6
	}

	// Suspicious DNS
	if chain.HasSuspiciousDNS {
		score += 0.3
	}

	return min(score, 1.0)
}

func (e *Engine) getSeverity(score float32) string {
	switch {
	case score >= 0.9:
		return "CRITICAL"
	case score >= 0.7:
		return "HIGH"
	case score >= 0.5:
		return "MEDIUM"
	case score >= 0.3:
		return "LOW"
	default:
		return "INFO"
	}
}

func (e *Engine) buildChainSummary(chain correlation.AttackChain) string {
	if len(chain.ProcessChain) == 0 {
		return "Unknown attack chain"
	}

	// Build process lineage string
	lineage := make([]string, 0)
	for _, proc := range chain.ProcessChain {
		lineage = append(lineage, proc.ProcessName)
	}

	summary := fmt.Sprintf("Process chain: %s", strings.Join(lineage, " → "))

	// Add key behaviors
	behaviors := make([]string, 0)

	if chain.HasEncodedCmd {
		behaviors = append(behaviors, "encoded command execution")
	}

	if chain.SensitiveFileAccessCount > 0 {
		behaviors = append(behaviors, fmt.Sprintf("accessed %d sensitive files", chain.SensitiveFileAccessCount))
	}

	if chain.NetworkConnectionCount > 0 {
		behaviors = append(behaviors, fmt.Sprintf("%d network connections", chain.NetworkConnectionCount))
	}

	if chain.HasPersistenceMechanism {
		behaviors = append(behaviors, "created persistence mechanism")
	}

	if chain.BeaconingScore > 0.7 {
		behaviors = append(behaviors, "C2 beaconing detected")
	}

	if len(behaviors) > 0 {
		summary += " | Behaviors: " + strings.Join(behaviors, ", ")
	}

	return summary
}

func (e *Engine) buildContext(chain correlation.AttackChain) map[string]interface{} {
	context := make(map[string]interface{})

	context["process_lineage_depth"] = chain.ProcessLineageDepth
	context["cmdline_length"] = chain.CmdlineLength
	context["cmdline_entropy"] = chain.CmdlineEntropy
	context["file_modifications"] = chain.FileModificationCount
	context["sensitive_file_access"] = chain.SensitiveFileAccessCount
	context["network_connections"] = chain.NetworkConnectionCount
	context["beaconing_score"] = chain.BeaconingScore
	context["has_persistence"] = chain.HasPersistenceMechanism
	context["has_privilege_escalation"] = chain.HasPrivilegeEscalation
	context["has_encoded_cmd"] = chain.HasEncodedCmd
	context["has_suspicious_dns"] = chain.HasSuspiciousDNS

	// Add process details
	if len(chain.ProcessChain) > 0 {
		lastProc := chain.ProcessChain[len(chain.ProcessChain)-1]
		context["final_process"] = lastProc.ProcessName
		context["final_commandline"] = lastProc.Commandline
		context["final_user"] = lastProc.Username
		context["is_elevated"] = lastProc.IsElevated
	}

	return context
}

func (e *Engine) getRecommendedAction(chain correlation.AttackChain, severity string) string {
	switch severity {
	case "CRITICAL":
		return "IMMEDIATE ACTION REQUIRED: Isolate endpoint, kill process tree, investigate for compromise, initiate incident response"
	case "HIGH":
		return "Investigate immediately, monitor process activity, consider containment if confirmed malicious"
	case "MEDIUM":
		return "Investigate when possible, correlate with other security events, update detection rules"
	case "LOW":
		return "Log for future analysis, review user behavior patterns"
	default:
		return "Monitor and log"
	}
}

func (e *Engine) Threshold() float32 {
	return e.threshold
}

func (t Threat) FormattedOutput() string {
	var sb strings.Builder

	sb.WriteString("╔═══════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                         🚨 THREAT DETECTED 🚨                                 ║\n")
	sb.WriteString("╚═══════════════════════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Threat Score:     %.2f / 1.00\n", t.Score))
	sb.WriteString(fmt.Sprintf("Severity:         %s\n", t.Severity))
	sb.WriteString(fmt.Sprintf("Timestamp:        %s\n\n", t.Timestamp.Format(time.RFC3339)))

	sb.WriteString("Attack Chain Summary:\n")
	sb.WriteString(fmt.Sprintf("  %s\n\n", t.AttackChainSummary))

	sb.WriteString("Scoring Breakdown:\n")
	sb.WriteString(fmt.Sprintf("  ├─ Rarity Score:    %.2f (weight: 30%%)\n", t.RarityScore))
	sb.WriteString(fmt.Sprintf("  ├─ Sequence Score:  %.2f (weight: 40%%)\n", t.SequenceScore))
	sb.WriteString(fmt.Sprintf("  └─ ML Score:        %.2f (weight: 30%%)\n\n", t.MLScore))

	if len(t.MitreTactics) > 0 {
		sb.WriteString("MITRE ATT&CK Tactics:\n")
		for _, tactic := range t.MitreTactics {
			sb.WriteString(fmt.Sprintf("  • %s\n", tactic))
		}
		sb.WriteString("\n")
	}

	if len(t.MitreTechniques) > 0 {
		sb.WriteString("MITRE ATT&CK Techniques:\n")
		for _, technique := range t.MitreTechniques {
			sb.WriteString(fmt.Sprintf("  • %s\n", technique))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Behavioral Context:\n")
	for key, value := range t.Context {
		sb.WriteString(fmt.Sprintf("  • %s: %v\n", key, value))
	}
	sb.WriteString("\n")

	sb.WriteString("Recommended Action:\n")
	sb.WriteString(fmt.Sprintf("  %s\n", t.RecommendedAction))

	sb.WriteString("\n╚═══════════════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
