package ml

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// ONNXEngine handles ML inference (currently using fallback rule-based mode)
// TODO: Integrate real ONNX Runtime when onnxruntime-go is available
type ONNXEngine struct {
	modelPath   string
	useFallback bool
}

// NewONNXEngine creates a new ONNX inference engine
func NewONNXEngine(modelPath string) (*ONNXEngine, error) {
	// Check if model file exists
	_, err := os.Stat(modelPath)
	if os.IsNotExist(err) {
		log.WithField("model_path", modelPath).Warn("Model file not found, using fallback rule-based mode")
	} else if err == nil {
		log.WithField("model_path", modelPath).Info("Model file found but ONNX Runtime not integrated yet, using fallback mode")
	}

	engine := &ONNXEngine{
		modelPath:   modelPath,
		useFallback: true, // Always use fallback for now
	}

	log.Info("ML engine initialized (fallback mode)")
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
