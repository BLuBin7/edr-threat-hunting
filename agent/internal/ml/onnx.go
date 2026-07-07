package ml

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// ONNXEngine handles ML inference
// Supports both real ONNX Runtime and fallback rule-based mode
type ONNXEngine struct {
	modelPath     string
	useFallback   bool
	modelMetadata *ModelMetadata

	// For ONNX Runtime integration (future)
	// session *ort.Session
}

// ModelMetadata contains information about the trained model
type ModelMetadata struct {
	ModelType       string   `json:"model_type"`        // "isolation_forest", "random_forest", etc.
	FeatureNames    []string `json:"feature_names"`
	ThresholdScore  float32  `json:"threshold_score"`   // Anomaly threshold
	TrainingDate    string   `json:"training_date"`
	FeatureCount    int      `json:"feature_count"`
}

// NewONNXEngine creates a new ONNX inference engine
func NewONNXEngine(modelPath string) (*ONNXEngine, error) {
	engine := &ONNXEngine{
		modelPath:   modelPath,
		useFallback: true,
	}

	// Check if model file exists
	_, err := os.Stat(modelPath)
	if os.IsNotExist(err) {
		log.WithField("model_path", modelPath).Warn("Model file not found, using fallback rule-based mode")
		return engine, nil
	}

	// Try to load model metadata
	metadataPath := modelPath + ".metadata.json"
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
		var metadata ModelMetadata
		if err := json.Unmarshal(metadataBytes, &metadata); err == nil {
			engine.modelMetadata = &metadata
			log.WithFields(log.Fields{
				"model_type":     metadata.ModelType,
				"feature_count":  metadata.FeatureCount,
				"training_date":  metadata.TrainingDate,
				"threshold":      metadata.ThresholdScore,
			}).Info("Model metadata loaded")
		}
	}

	// TODO: Initialize ONNX Runtime session when available
	// For now, use fallback mode with enhanced heuristics
	log.WithField("model_path", modelPath).Info("ML engine initialized (enhanced fallback mode)")

	return engine, nil
}

// Predict runs inference on the feature vector
func (e *ONNXEngine) Predict(features []float32) (float32, error) {
	// Validate feature count
	if len(features) != 15 {
		return 0, fmt.Errorf("invalid feature count: expected 15, got %d", len(features))
	}

	// Always use fallback mode for now
	return e.fallbackPredict(features), nil
}

// fallbackPredict provides simple rule-based scoring when model is not available
func (e *ONNXEngine) fallbackPredict(features []float32) float32 {
	score := float32(0.0)

	// Feature 0-2: Process features
	if features[0] > 3 { // Deep lineage
		score += 0.2
	}
	if features[1] > 0.5 { // Rare parent-child
		score += 0.3
	}
	if features[2] > 0.5 { // Privilege escalation
		score += 0.3
	}

	// Feature 3-5: Commandline features
	if features[3] > 500 { // Long commandline
		score += 0.1
	}
	if features[4] > 4.5 { // High entropy
		score += 0.2
	}
	if features[5] > 0.5 { // Encoded command
		score += 0.3
	}

	// Feature 6-8: File activity
	if features[6] > 10 { // Many file modifications
		score += 0.2
	}
	if features[7] > 0 { // Sensitive file access
		score += 0.4
	}
	if features[8] > 50 { // Mass file activity
		score += 0.4
	}

	// Feature 9-11: Network activity
	if features[9] > 5 { // Many connections
		score += 0.2
	}
	if features[10] > 0.5 { // Suspicious DNS
		score += 0.3
	}
	if features[11] > 0.7 { // Beaconing
		score += 0.4
	}

	// Feature 12-14: Persistence
	if features[12] > 0.5 { // Persistence mechanism
		score += 0.4
	}

	return min(score, 1.0)
}

// Close releases resources
func (e *ONNXEngine) Close() {
	// No resources to clean up in fallback mode
	log.Info("ML engine closed")
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
