package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
	ort "github.com/yalue/onnxruntime_go"
)

var (
	ortInitOnce sync.Once
	ortInitErr  error
)

// ModelMetadata contains information about the trained model
type ModelMetadata struct {
	ModelType      string   `json:"model_type"`      // "isolation_forest", "random_forest", etc.
	FeatureNames   []string `json:"feature_names"`
	ThresholdScore float32  `json:"threshold_score"` // Anomaly threshold
	TrainingDate   string   `json:"training_date"`
	FeatureCount   int      `json:"feature_count"`
}

// ONNXEngine handles ML inference
// Supports both real ONNX Runtime and fallback rule-based mode
type ONNXEngine struct {
	modelPath     string
	libraryPath   string
	useFallback   bool
	modelMetadata *ModelMetadata

	// ONNX Runtime session and tensors
	session     *ort.AdvancedSession
	inputTensor *ort.Tensor[float32]
	outputLabel *ort.Tensor[int64]
	outputScore *ort.Tensor[float32]
}

// NewONNXEngine creates a new ONNX inference engine
func NewONNXEngine(modelPath string, libraryPath string) (*ONNXEngine, error) {
	engine := &ONNXEngine{
		modelPath:   modelPath,
		libraryPath: libraryPath,
		useFallback: true,
	}

	// 1. Check if model file exists
	_, err := os.Stat(modelPath)
	if os.IsNotExist(err) {
		log.WithField("model_path", modelPath).Warn("Model file not found, using fallback rule-based mode")
		return engine, nil
	}

	// 2. Try to load model metadata
	metadataPath := modelPath + ".metadata.json"
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
		var metadata ModelMetadata
		if err := json.Unmarshal(metadataBytes, &metadata); err == nil {
			engine.modelMetadata = &metadata
			log.WithFields(log.Fields{
				"model_type":    metadata.ModelType,
				"feature_count": metadata.FeatureCount,
				"training_date": metadata.TrainingDate,
				"threshold":     metadata.ThresholdScore,
			}).Info("Model metadata loaded")
		} else {
			log.WithError(err).Warn("Failed to parse model metadata")
		}
	} else {
		log.WithField("metadata_path", metadataPath).Warn("Model metadata file not found, using default 15 features")
	}

	// If metadata failed to load, set default feature count to 15
	if engine.modelMetadata == nil {
		engine.modelMetadata = &ModelMetadata{
			ModelType:    "isolation_forest",
			FeatureCount: 15,
		}
	}

	// 3. Try to initialize ONNX Runtime
	err = engine.initializeONNX()
	if err != nil {
		log.WithError(err).Warn("Failed to initialize ONNX Runtime, falling back to rule-based mode")
		engine.useFallback = true
	} else {
		engine.useFallback = false
		log.WithField("model_path", modelPath).Info("ML engine initialized with ONNX Runtime")
	}

	return engine, nil
}

// findSharedLibrary searches standard paths for the onnxruntime shared library
func findSharedLibrary(configuredPath string) string {
	if configuredPath != "" {
		if _, err := os.Stat(configuredPath); err == nil {
			return configuredPath
		}
		log.WithField("configured_path", configuredPath).Warn("Configured onnxruntime library path not found, searching standard paths")
	}

	var libName string
	var searchPaths []string

	switch runtime.GOOS {
	case "darwin":
		libName = "libonnxruntime.dylib"
		searchPaths = []string{
			"/opt/homebrew/lib/" + libName,
			"/usr/local/lib/" + libName,
			"./" + libName,
			"../" + libName,
		}
	case "linux":
		libName = "libonnxruntime.so"
		searchPaths = []string{
			"/usr/lib/" + libName,
			"/usr/local/lib/" + libName,
			"/usr/lib/x86_64-linux-gnu/" + libName,
			"/usr/lib/aarch64-linux-gnu/" + libName,
			"./" + libName,
			"../" + libName,
		}
	default:
		return ""
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// initializeONNX sets up the ONNX Runtime session and tensors
func (e *ONNXEngine) initializeONNX() error {
	// Find and load the shared library
	libPath := findSharedLibrary(e.libraryPath)
	if libPath == "" {
		return fmt.Errorf("onnxruntime shared library not found. Please install onnxruntime")
	}

	log.WithField("lib_path", libPath).Info("Loading onnxruntime shared library")

	// Initialize the environment (thread-safe once)
	ortInitOnce.Do(func() {
		ort.SetSharedLibraryPath(libPath)
		ortInitErr = ort.InitializeEnvironment()
	})

	if ortInitErr != nil {
		return fmt.Errorf("failed to initialize ONNX Runtime environment: %w", ortInitErr)
	}

	// Create input and output tensors
	inputShape := ort.NewShape(1, int64(e.modelMetadata.FeatureCount))
	inputTensor, err := ort.NewEmptyTensor[float32](inputShape)
	if err != nil {
		return fmt.Errorf("failed to create input tensor: %w", err)
	}
	e.inputTensor = inputTensor

	outputLabelShape := ort.NewShape(1, 1)
	outputLabel, err := ort.NewEmptyTensor[int64](outputLabelShape)
	if err != nil {
		e.inputTensor.Destroy()
		return fmt.Errorf("failed to create output label tensor: %w", err)
	}
	e.outputLabel = outputLabel

	outputScoreShape := ort.NewShape(1, 1)
	outputScore, err := ort.NewEmptyTensor[float32](outputScoreShape)
	if err != nil {
		e.inputTensor.Destroy()
		e.outputLabel.Destroy()
		return fmt.Errorf("failed to create output score tensor: %w", err)
	}
	e.outputScore = outputScore

	// Create session
	inputNames := []string{"float_input"}
	outputNames := []string{"label", "scores"}
	inputs := []ort.Value{e.inputTensor}
	outputs := []ort.Value{e.outputLabel, e.outputScore}

	session, err := ort.NewAdvancedSession(e.modelPath, inputNames, outputNames, inputs, outputs, nil)
	if err != nil {
		e.inputTensor.Destroy()
		e.outputLabel.Destroy()
		e.outputScore.Destroy()
		return fmt.Errorf("failed to create advanced session: %w", err)
	}
	e.session = session

	return nil
}

// Predict runs inference on the feature vector
func (e *ONNXEngine) Predict(features []float32) (float32, error) {
	// Validate feature count
	expectedFeatures := e.modelMetadata.FeatureCount
	if len(features) != expectedFeatures {
		return 0, fmt.Errorf("invalid feature count: expected %d, got %d", expectedFeatures, len(features))
	}

	// Fallback mode if ONNX Runtime is not initialized
	if e.useFallback {
		return e.fallbackPredict(features), nil
	}

	// Copy features to input tensor data buffer
	inputData := e.inputTensor.GetData()
	copy(inputData, features)

	// Run inference
	err := e.session.Run()
	if err != nil {
		return 0, fmt.Errorf("onnx run failed: %w", err)
	}

	// Read outputs
	labelVal := e.outputLabel.GetData()[0]       // -1 = anomaly, 1 = normal
	decisionScore := e.outputScore.GetData()[0] // raw decision score (negative = anomaly)

	// Map decision score to [0.0, 1.0] anomaly score where higher is more anomalous
	// In Isolation Forest, decision_score is typically in [-0.5, 0.5] range.
	// anomaly_score = 0.5 - decision_score
	anomalyScore := float32(0.5) - decisionScore
	if labelVal == -1 && anomalyScore < 0.7 {
		// Ensure label match aligns with scoring
		anomalyScore = 0.75
	}

	// Bound the score to [0.0, 1.0]
	if anomalyScore < 0 {
		anomalyScore = 0
	} else if anomalyScore > 1 {
		anomalyScore = 1
	}

	log.WithFields(log.Fields{
		"label":          labelVal,
		"decision_score": decisionScore,
		"anomaly_score":  anomalyScore,
	}).Debug("ONNX inference complete")

	return anomalyScore, nil
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
	if e.session != nil {
		e.session.Destroy()
	}
	if e.inputTensor != nil {
		e.inputTensor.Destroy()
	}
	if e.outputLabel != nil {
		e.outputLabel.Destroy()
	}
	if e.outputScore != nil {
		e.outputScore.Destroy()
	}
	log.Info("ML engine closed")
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
