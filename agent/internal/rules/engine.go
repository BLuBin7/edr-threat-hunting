package rules

import (
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Engine evaluates events against loaded rules
type Engine struct {
	loader *Loader
	mu     sync.RWMutex

	// Statistics
	totalEvaluations int64
	totalMatches     int64
	ruleMatches      map[string]int64 // rule name -> match count

	// Cache for compiled regexes
	regexCache map[string]*regexp.Regexp
	regexMu    sync.RWMutex
}

// NewEngine creates a new rules engine
func NewEngine(rulesDir string) (*Engine, error) {
	loader, err := NewLoader(rulesDir)
	if err != nil {
		return nil, err
	}

	engine := &Engine{
		loader:      loader,
		ruleMatches: make(map[string]int64),
		regexCache:  make(map[string]*regexp.Regexp),
	}

	// Set up callbacks for rule lifecycle
	loader.SetCallbacks(
		func(rule *Rule) {
			log.Printf("[INFO] Rule loaded: %s (severity=%s, category=%s)",
				rule.Name, rule.Severity, rule.Category)
		},
		func(name string) {
			log.Printf("[INFO] Rule unloaded: %s", name)
			engine.mu.Lock()
			delete(engine.ruleMatches, name)
			engine.mu.Unlock()
		},
		func(old, new *Rule) {
			log.Printf("[INFO] Rule updated: %s (severity=%s->%s)",
				new.Name, old.Severity, new.Severity)
		},
	)

	return engine, nil
}

// Start loads rules and starts watching
func (e *Engine) Start() error {
	if err := e.loader.LoadAll(); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	if err := e.loader.StartWatching(); err != nil {
		return fmt.Errorf("failed to start watching: %w", err)
	}

	return nil
}

// Evaluate checks an event against all enabled rules
func (e *Engine) Evaluate(event map[string]interface{}) []*MatchResult {
	e.mu.Lock()
	e.totalEvaluations++
	e.mu.Unlock()

	rules := e.loader.GetAllRules()
	var matches []*MatchResult

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if matched, matchedFields := e.evaluateRule(rule, event); matched {
			result := &MatchResult{
				Matched:       true,
				Rule:          rule,
				MatchedFields: matchedFields,
				Timestamp:     time.Now(),
			}

			if eventID, ok := event["event_id"].(string); ok {
				result.EventID = eventID
			}

			matches = append(matches, result)

			// Update statistics
			e.mu.Lock()
			e.totalMatches++
			e.ruleMatches[rule.Name]++
			rule.MatchCount++
			e.mu.Unlock()

			log.Printf("[MATCH] Rule '%s' matched (severity=%s, score_modifier=%.2f)",
				rule.Name, rule.Severity, rule.ScoreModifier)
		}
	}

	return matches
}

// evaluateRule checks if a single rule matches an event
func (e *Engine) evaluateRule(rule *Rule, event map[string]interface{}) (bool, []string) {
	var matchedFields []string

	// All conditions must match (AND logic)
	for _, condition := range rule.Conditions {
		matched := e.evaluateCondition(condition, event)

		// Handle negation
		if condition.Negate {
			matched = !matched
		}

		if !matched {
			return false, nil
		}

		matchedFields = append(matchedFields, condition.Field)
	}

	return true, matchedFields
}

// evaluateCondition checks a single condition
func (e *Engine) evaluateCondition(cond Condition, event map[string]interface{}) bool {
	// Extract field value from event (support nested fields like "process.commandline")
	fieldValue := e.getFieldValue(event, cond.Field)
	if fieldValue == nil {
		return false
	}

	switch cond.Operator {
	case "equals", "eq", "==":
		return e.evalEquals(fieldValue, cond.Value)

	case "contains":
		return e.evalContains(fieldValue, cond.Value)

	case "startswith":
		return e.evalStartsWith(fieldValue, cond.Value)

	case "endswith":
		return e.evalEndsWith(fieldValue, cond.Value)

	case "regex", "matches":
		return e.evalRegex(fieldValue, cond.Value)

	case "in":
		return e.evalIn(fieldValue, cond.Value)

	case "gt", ">":
		return e.evalGreaterThan(fieldValue, cond.Value)

	case "lt", "<":
		return e.evalLessThan(fieldValue, cond.Value)

	case "gte", ">=":
		return e.evalGreaterThanOrEqual(fieldValue, cond.Value)

	case "lte", "<=":
		return e.evalLessThanOrEqual(fieldValue, cond.Value)

	default:
		log.Printf("[WARN] Unknown operator: %s", cond.Operator)
		return false
	}
}

// getFieldValue extracts nested field from event (e.g., "process.commandline")
func (e *Engine) getFieldValue(event map[string]interface{}, field string) interface{} {
	parts := strings.Split(field, ".")
	current := event

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - return value
			return current[part]
		}

		// Navigate deeper
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}

	return nil
}

// Evaluation helpers

func (e *Engine) evalEquals(field, expected interface{}) bool {
	return fmt.Sprintf("%v", field) == fmt.Sprintf("%v", expected)
}

func (e *Engine) evalContains(field, value interface{}) bool {
	fieldStr := strings.ToLower(fmt.Sprintf("%v", field))

	switch v := value.(type) {
	case string:
		return strings.Contains(fieldStr, strings.ToLower(v))
	case []interface{}:
		// Check if field contains ANY of the strings
		for _, item := range v {
			if itemStr, ok := item.(string); ok {
				if strings.Contains(fieldStr, strings.ToLower(itemStr)) {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) evalStartsWith(field, value interface{}) bool {
	fieldStr := strings.ToLower(fmt.Sprintf("%v", field))
	valueStr := strings.ToLower(fmt.Sprintf("%v", value))
	return strings.HasPrefix(fieldStr, valueStr)
}

func (e *Engine) evalEndsWith(field, value interface{}) bool {
	fieldStr := strings.ToLower(fmt.Sprintf("%v", field))
	valueStr := strings.ToLower(fmt.Sprintf("%v", value))
	return strings.HasSuffix(fieldStr, valueStr)
}

func (e *Engine) evalRegex(field, pattern interface{}) bool {
	fieldStr := fmt.Sprintf("%v", field)
	patternStr := fmt.Sprintf("%v", pattern)

	// Use cached regex if available
	e.regexMu.RLock()
	re, exists := e.regexCache[patternStr]
	e.regexMu.RUnlock()

	if !exists {
		var err error
		re, err = regexp.Compile(patternStr)
		if err != nil {
			log.Printf("[ERROR] Invalid regex pattern '%s': %v", patternStr, err)
			return false
		}

		e.regexMu.Lock()
		e.regexCache[patternStr] = re
		e.regexMu.Unlock()
	}

	return re.MatchString(fieldStr)
}

func (e *Engine) evalIn(field, list interface{}) bool {
	fieldStr := fmt.Sprintf("%v", field)

	switch v := list.(type) {
	case []interface{}:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == fieldStr {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == fieldStr {
				return true
			}
		}
	}
	return false
}

func (e *Engine) evalGreaterThan(field, threshold interface{}) bool {
	fieldNum := e.toFloat(field)
	thresholdNum := e.toFloat(threshold)
	return fieldNum > thresholdNum
}

func (e *Engine) evalLessThan(field, threshold interface{}) bool {
	fieldNum := e.toFloat(field)
	thresholdNum := e.toFloat(threshold)
	return fieldNum < thresholdNum
}

func (e *Engine) evalGreaterThanOrEqual(field, threshold interface{}) bool {
	fieldNum := e.toFloat(field)
	thresholdNum := e.toFloat(threshold)
	return fieldNum >= thresholdNum
}

func (e *Engine) evalLessThanOrEqual(field, threshold interface{}) bool {
	fieldNum := e.toFloat(field)
	thresholdNum := e.toFloat(threshold)
	return fieldNum <= thresholdNum
}

func (e *Engine) toFloat(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		var f float64
		fmt.Sscanf(v, "%f", &f)
		return f
	default:
		return math.NaN()
	}
}

// GetStats returns engine statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ruleSet := e.loader.GetRuleSet()

	return map[string]interface{}{
		"total_rules":       ruleSet.TotalRules,
		"enabled_rules":     ruleSet.EnabledRules,
		"total_evaluations": e.totalEvaluations,
		"total_matches":     e.totalMatches,
		"categories":        ruleSet.Categories,
		"top_rules":         e.getTopMatchedRules(5),
	}
}

func (e *Engine) getTopMatchedRules(limit int) []map[string]interface{} {
	type ruleStat struct {
		name   string
		count  int64
	}

	var stats []ruleStat
	for name, count := range e.ruleMatches {
		stats = append(stats, ruleStat{name, count})
	}

	// Simple bubble sort (small dataset)
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].count > stats[i].count {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	// Limit results
	if len(stats) > limit {
		stats = stats[:limit]
	}

	result := make([]map[string]interface{}, len(stats))
	for i, s := range stats {
		result[i] = map[string]interface{}{
			"rule":  s.name,
			"count": s.count,
		}
	}

	return result
}

// Stop stops the engine
func (e *Engine) Stop() error {
	return e.loader.Stop()
}
