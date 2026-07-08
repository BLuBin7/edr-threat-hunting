package analytics

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// RarityEngine detects behavioral rarity using frequency-based analysis
// Implements adaptive baselines per environment
type RarityEngine struct {
	mu sync.RWMutex

	// Frequency tracking
	processLineages     map[string]*FrequencyCounter // parent->child patterns
	commandPatterns     map[string]*FrequencyCounter // command signatures
	fileAccessPatterns  map[string]*FrequencyCounter // file access patterns
	networkConnections  map[string]*FrequencyCounter // network endpoints
	userBehaviors       map[string]*FrequencyCounter // user activity patterns

	// Baseline learning
	baselineWindow      time.Duration
	baselineStartTime   time.Time
	learningMode        bool

	// Adaptive thresholds
	rarityThreshold     float32
	veryRareThreshold   float32

	// Decay parameters
	decayFactor         float64
	lastDecayTime       time.Time

	// Statistics
	totalObservations   uint64
	rareEventsDetected  uint64
}

// FrequencyCounter tracks occurrence frequency with time decay
type FrequencyCounter struct {
	Count           uint64
	FirstSeen       time.Time
	LastSeen        time.Time
	DecayedCount    float64
}

// RarityScore represents the rarity assessment of a behavior
type RarityScore struct {
	Overall             float32
	ProcessLineage      float32
	CommandPattern      float32
	FileAccess          float32
	NetworkConnection   float32
	UserBehavior        float32
	IsRare              bool
	IsVeryRare          bool
	Explanation         string
}

// NewRarityEngine creates a new behavioral rarity engine
func NewRarityEngine(baselineWindowHours int) *RarityEngine {
	return &RarityEngine{
		processLineages:    make(map[string]*FrequencyCounter),
		commandPatterns:    make(map[string]*FrequencyCounter),
		fileAccessPatterns: make(map[string]*FrequencyCounter),
		networkConnections: make(map[string]*FrequencyCounter),
		userBehaviors:      make(map[string]*FrequencyCounter),
		baselineWindow:     time.Duration(baselineWindowHours) * time.Hour,
		baselineStartTime:  time.Now(),
		learningMode:       true,
		rarityThreshold:    0.05,  // Events occurring < 5% frequency
		veryRareThreshold:  0.01,  // Events occurring < 1% frequency
		decayFactor:        0.95,  // 5% decay per day
		lastDecayTime:      time.Now(),
	}
}

// AnalyzeRarity computes rarity score for a behavioral event
func (r *RarityEngine) AnalyzeRarity(
	processLineage string,
	commandLine string,
	filePath string,
	networkEndpoint string,
	username string,
) *RarityScore {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.totalObservations++

	// Update frequency counters
	r.updateCounter(r.processLineages, processLineage)
	r.updateCounter(r.commandPatterns, r.extractCommandPattern(commandLine))
	r.updateCounter(r.fileAccessPatterns, filePath)
	r.updateCounter(r.networkConnections, networkEndpoint)
	r.updateCounter(r.userBehaviors, r.buildUserBehaviorKey(username, processLineage))

	// Check if still in learning mode
	if time.Since(r.baselineStartTime) < r.baselineWindow {
		return &RarityScore{
			Overall:     0.0,
			IsRare:      false,
			Explanation: "Learning mode - building baseline",
		}
	}

	// Exit learning mode
	if r.learningMode {
		r.learningMode = false
		log.WithFields(log.Fields{
			"baseline_hours":        r.baselineWindow.Hours(),
			"total_observations":    r.totalObservations,
			"unique_lineages":       len(r.processLineages),
			"unique_commands":       len(r.commandPatterns),
			"unique_file_accesses":  len(r.fileAccessPatterns),
			"unique_net_endpoints":  len(r.networkConnections),
		}).Info("Rarity engine baseline learning completed")
	}

	// Apply time decay
	r.applyDecay()

	// Calculate individual rarity scores
	score := &RarityScore{}
	score.ProcessLineage = r.calculateRarity(r.processLineages, processLineage)
	score.CommandPattern = r.calculateRarity(r.commandPatterns, r.extractCommandPattern(commandLine))
	score.FileAccess = r.calculateRarity(r.fileAccessPatterns, filePath)
	score.NetworkConnection = r.calculateRarity(r.networkConnections, networkEndpoint)
	score.UserBehavior = r.calculateRarity(r.userBehaviors, r.buildUserBehaviorKey(username, processLineage))

	// Compute weighted overall score
	// Higher weight on process lineage and command patterns (stronger signals)
	score.Overall = (score.ProcessLineage * 0.30) +
		(score.CommandPattern * 0.25) +
		(score.FileAccess * 0.20) +
		(score.NetworkConnection * 0.15) +
		(score.UserBehavior * 0.10)

	// Classify rarity
	score.IsVeryRare = score.Overall >= r.veryRareThreshold
	score.IsRare = score.Overall >= r.rarityThreshold

	if score.IsRare {
		r.rareEventsDetected++
		score.Explanation = r.buildExplanation(score)
	}

	return score
}

// updateCounter updates or creates a frequency counter
func (r *RarityEngine) updateCounter(counters map[string]*FrequencyCounter, key string) {
	if key == "" {
		return
	}

	counter, exists := counters[key]
	if !exists {
		counters[key] = &FrequencyCounter{
			Count:        1,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			DecayedCount: 1.0,
		}
	} else {
		counter.Count++
		counter.LastSeen = time.Now()
		counter.DecayedCount++
	}
}

// calculateRarity computes rarity score (0.0 = common, 1.0 = very rare)
func (r *RarityEngine) calculateRarity(counters map[string]*FrequencyCounter, key string) float32 {
	if key == "" {
		return 0.0
	}

	counter, exists := counters[key]
	if !exists {
		// Never seen before = maximum rarity
		return 1.0
	}

	// Calculate relative frequency
	totalDecayedCount := r.getTotalDecayedCount(counters)
	if totalDecayedCount == 0 {
		return 0.0
	}

	relativeFrequency := counter.DecayedCount / totalDecayedCount

	// Convert to rarity score (inverse of frequency)
	rarityScore := 1.0 - relativeFrequency

	return float32(math.Min(rarityScore, 1.0))
}

// getTotalDecayedCount sums all decayed counts
func (r *RarityEngine) getTotalDecayedCount(counters map[string]*FrequencyCounter) float64 {
	total := 0.0
	for _, counter := range counters {
		total += counter.DecayedCount
	}
	return total
}

// applyDecay applies exponential time decay to counters
func (r *RarityEngine) applyDecay() {
	daysSinceLastDecay := time.Since(r.lastDecayTime).Hours() / 24.0
	if daysSinceLastDecay < 1.0 {
		return // Apply decay once per day
	}

	decayMultiplier := math.Pow(r.decayFactor, daysSinceLastDecay)

	// Apply decay to all counters
	for _, counter := range r.processLineages {
		counter.DecayedCount *= decayMultiplier
	}
	for _, counter := range r.commandPatterns {
		counter.DecayedCount *= decayMultiplier
	}
	for _, counter := range r.fileAccessPatterns {
		counter.DecayedCount *= decayMultiplier
	}
	for _, counter := range r.networkConnections {
		counter.DecayedCount *= decayMultiplier
	}
	for _, counter := range r.userBehaviors {
		counter.DecayedCount *= decayMultiplier
	}

	r.lastDecayTime = time.Now()

	log.WithFields(log.Fields{
		"days_elapsed":     daysSinceLastDecay,
		"decay_multiplier": decayMultiplier,
	}).Debug("Applied time decay to rarity counters")
}

// extractCommandPattern extracts normalized command pattern
func (r *RarityEngine) extractCommandPattern(cmdline string) string {
	if cmdline == "" {
		return ""
	}

	// Hash the command pattern to create a signature
	// This captures command structure while ignoring variable arguments
	hash := sha256.Sum256([]byte(cmdline))
	return fmt.Sprintf("cmd_%x", hash[:8])
}

// buildUserBehaviorKey creates composite key for user behavior tracking
func (r *RarityEngine) buildUserBehaviorKey(username, processLineage string) string {
	if username == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", username, processLineage)
}

// buildExplanation generates human-readable explanation
func (r *RarityEngine) buildExplanation(score *RarityScore) string {
	explanation := "Rare behavioral pattern detected: "

	components := []string{}
	if score.ProcessLineage > r.rarityThreshold {
		components = append(components, fmt.Sprintf("unusual process lineage (%.2f)", score.ProcessLineage))
	}
	if score.CommandPattern > r.rarityThreshold {
		components = append(components, fmt.Sprintf("rare command pattern (%.2f)", score.CommandPattern))
	}
	if score.FileAccess > r.rarityThreshold {
		components = append(components, fmt.Sprintf("uncommon file access (%.2f)", score.FileAccess))
	}
	if score.NetworkConnection > r.rarityThreshold {
		components = append(components, fmt.Sprintf("unusual network endpoint (%.2f)", score.NetworkConnection))
	}
	if score.UserBehavior > r.rarityThreshold {
		components = append(components, fmt.Sprintf("atypical user behavior (%.2f)", score.UserBehavior))
	}

	for i, comp := range components {
		if i > 0 {
			explanation += ", "
		}
		explanation += comp
	}

	return explanation
}

// GetStats returns rarity engine statistics
func (r *RarityEngine) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rareEventRate := float64(0)
	if r.totalObservations > 0 {
		rareEventRate = float64(r.rareEventsDetected) / float64(r.totalObservations)
	}

	return map[string]interface{}{
		"learning_mode":         r.learningMode,
		"total_observations":    r.totalObservations,
		"rare_events_detected":  r.rareEventsDetected,
		"rare_event_rate":       rareEventRate,
		"unique_lineages":       len(r.processLineages),
		"unique_commands":       len(r.commandPatterns),
		"unique_file_accesses":  len(r.fileAccessPatterns),
		"unique_net_endpoints":  len(r.networkConnections),
		"unique_user_behaviors": len(r.userBehaviors),
		"baseline_hours":        r.baselineWindow.Hours(),
	}
}

// Reset clears all counters and restarts learning mode
func (r *RarityEngine) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.processLineages = make(map[string]*FrequencyCounter)
	r.commandPatterns = make(map[string]*FrequencyCounter)
	r.fileAccessPatterns = make(map[string]*FrequencyCounter)
	r.networkConnections = make(map[string]*FrequencyCounter)
	r.userBehaviors = make(map[string]*FrequencyCounter)
	r.baselineStartTime = time.Now()
	r.learningMode = true
	r.totalObservations = 0
	r.rareEventsDetected = 0

	log.Info("Rarity engine reset - baseline learning restarted")
}
