package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/binhbl/edr-threat-hunting/agent/internal/config"
	"github.com/binhbl/edr-threat-hunting/agent/internal/correlation"
	"github.com/binhbl/edr-threat-hunting/agent/internal/ml"
	"github.com/binhbl/edr-threat-hunting/agent/internal/monitors"
	"github.com/binhbl/edr-threat-hunting/agent/internal/scoring"
	"github.com/binhbl/edr-threat-hunting/agent/pkg/metrics"
	log "github.com/sirupsen/logrus"
)

var (
	configPath = flag.String("config", "/etc/edr-agent/config.yaml", "Path to configuration file")
	version    = "1.0.0"
	buildTime  = "unknown"
)

func main() {
	flag.Parse()

	// Setup logging
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	log.WithFields(log.Fields{
		"version":   version,
		"buildTime": buildTime,
	}).Info("EDR Threat Hunting Agent starting...")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize metrics exporter
	metricsExporter := metrics.NewPrometheusExporter(cfg.Metrics.Port)
	go metricsExporter.Start()

	// Initialize context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize ML inference engine
	mlEngine, err := ml.NewONNXEngine(cfg.ML.ModelPath)
	if err != nil {
		log.Fatalf("Failed to initialize ML engine: %v", err)
	}
	defer mlEngine.Close()
	log.WithField("model", cfg.ML.ModelPath).Info("ML engine initialized")

	// Initialize behavioral correlation engine
	correlationEngine := correlation.NewEngine(
		correlation.WithWindowSize(cfg.Correlation.WindowSize),
		correlation.WithMaxMemory(cfg.Correlation.MaxMemoryMB),
	)
	log.Info("Behavioral correlation engine initialized")

	// Initialize threat scoring engine
	scoringEngine := scoring.NewEngine(
		scoring.WithRarityWeight(cfg.Scoring.RarityWeight),
		scoring.WithSequenceWeight(cfg.Scoring.SequenceWeight),
		scoring.WithMLWeight(cfg.Scoring.MLWeight),
		scoring.WithThreshold(cfg.Scoring.Threshold),
	)
	log.Info("Threat scoring engine initialized")

	// Channel for telemetry events
	eventChan := make(chan monitors.Event, 10000)

	// Initialize and start monitors
	log.Info("Starting telemetry monitors...")

	// 1. Process Monitor
	processMonitor := monitors.NewProcessMonitor(cfg.Monitors.Process)
	go processMonitor.Start(ctx, eventChan)
	log.Info("Process monitor started")

	// 2. File Monitor
	fileMonitor, err := monitors.NewFileMonitor(cfg.Monitors.File)
	if err != nil {
		log.Fatalf("Failed to initialize file monitor: %v", err)
	}
	go fileMonitor.Start(ctx, eventChan)
	log.Info("File monitor started")

	// 3. Network Monitor
	networkMonitor := monitors.NewNetworkMonitor(cfg.Monitors.Network)
	go networkMonitor.Start(ctx, eventChan)
	log.Info("Network monitor started")

	// 4. Persistence Monitor
	persistenceMonitor, err := monitors.NewPersistenceMonitor(cfg.Monitors.Persistence)
	if err != nil {
		log.Fatalf("Failed to initialize persistence monitor: %v", err)
	}
	go persistenceMonitor.Start(ctx, eventChan)
	log.Info("Persistence monitor started")

	// Start main event processing loop
	go processEvents(ctx, eventChan, correlationEngine, mlEngine, scoringEngine, metricsExporter)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.WithField("signal", sig).Info("Received shutdown signal, gracefully shutting down...")
	cancel()

	// Give goroutines time to cleanup
	time.Sleep(2 * time.Second)
	log.Info("EDR Agent stopped")
}

func processEvents(
	ctx context.Context,
	eventChan <-chan monitors.Event,
	correlationEngine *correlation.Engine,
	mlEngine *ml.ONNXEngine,
	scoringEngine *scoring.Engine,
	metricsExporter *metrics.PrometheusExporter,
) {
	eventCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("Event processor shutting down...")
			return
		case event := <-eventChan:
			eventCount++
			metricsExporter.IncEventsProcessed(event.Type.String())

			// Step 1: Add event to correlation engine (sliding window)
			correlationEngine.AddEvent(event)

			// Step 2: Check if this event triggers a suspicious sequence
			attackChains := correlationEngine.GetAttackChains(event)
			if len(attackChains) == 0 {
				continue
			}

			// Step 3: Extract features for ML inference
			for _, chain := range attackChains {
				features := extractFeatures(chain)

				// Step 4: Run ML inference
				startInference := time.Now()
				mlScore, err := mlEngine.Predict(features)
				inferenceLatency := time.Since(startInference)
				metricsExporter.ObserveInferenceLatency(inferenceLatency.Seconds())

				if err != nil {
					log.WithError(err).Warn("ML inference failed")
					mlScore = 0.0 // fallback
				}

				// Step 5: Calculate final threat score
				threat := scoringEngine.Calculate(chain, mlScore)

				// Step 6: If score exceeds threshold, generate alert
				if threat.Score >= scoringEngine.Threshold() {
					metricsExporter.IncAlertsGenerated(threat.Severity)
					logThreatAlert(threat)

					// TODO: Send to VictoriaMetrics / ClickHouse
				}

				if eventCount%1000 == 0 {
					log.WithFields(log.Fields{
						"events_processed": eventCount,
						"memory_mb":        correlationEngine.MemoryUsageMB(),
						"chains_tracked":   correlationEngine.ChainCount(),
					}).Debug("Processing stats")
				}
			}
		}
	}
}

func extractFeatures(chain correlation.AttackChain) []float32 {
	// Feature engineering for ML model
	// Total 15 features matching the trained Isolation Forest model
	features := make([]float32, 15)

	// Feature 1-3: Process lineage depth, rare parent-child, privilege escalation
	features[0] = float32(chain.ProcessLineageDepth)
	features[1] = boolToFloat(chain.IsRareParentChild)
	features[2] = boolToFloat(chain.HasPrivilegeEscalation)

	// Feature 4-6: Commandline features
	features[3] = float32(chain.CmdlineLength)
	features[4] = chain.CmdlineEntropy
	features[5] = boolToFloat(chain.HasEncodedCmd)

	// Feature 7-9: File activity
	features[6] = float32(chain.FileModificationCount)
	features[7] = float32(chain.SensitiveFileAccessCount)
	features[8] = chain.MassFileActivityRate

	// Feature 10-12: Network activity
	features[9] = float32(chain.NetworkConnectionCount)
	features[10] = boolToFloat(chain.HasSuspiciousDNS)
	features[11] = chain.BeaconingScore

	// Feature 13-15: Persistence activity
	features[12] = boolToFloat(chain.HasPersistenceMechanism)
	features[13] = float32(chain.CronJobCount)
	features[14] = float32(chain.ServiceCreationCount)

	return features
}

func boolToFloat(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}

func logThreatAlert(threat scoring.Threat) {
	log.WithFields(log.Fields{
		"threat_score":       fmt.Sprintf("%.2f", threat.Score),
		"severity":           threat.Severity,
		"attack_chain":       threat.AttackChainSummary,
		"behavioral_context": threat.Context,
		"mitre_tactics":      threat.MitreTactics,
		"recommended_action": threat.RecommendedAction,
	}).Warn("THREAT DETECTED")

	// Pretty print attack chain
	fmt.Println("\n" + threat.FormattedOutput())
}
