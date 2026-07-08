package rules

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
	"log"
)

// Loader handles loading and hot-reloading of YAML rules
type Loader struct {
	rulesDir string
	rules    map[string]*Rule // name -> rule
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}

	// Callbacks
	onRuleLoaded   func(*Rule)
	onRuleUnloaded func(string)
	onRuleUpdated  func(*Rule, *Rule) // old, new
}

// NewLoader creates a new rule loader
func NewLoader(rulesDir string) (*Loader, error) {
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("rules directory does not exist: %s", rulesDir)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	l := &Loader{
		rulesDir: rulesDir,
		rules:    make(map[string]*Rule),
		watcher:  watcher,
		stopCh:   make(chan struct{}),
	}

	return l, nil
}

// LoadAll loads all YAML files from rules directory
func (l *Loader) LoadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(l.rulesDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to glob rules: %w", err)
	}

	yamlFiles, err := filepath.Glob(filepath.Join(l.rulesDir, "*.yml"))
	if err != nil {
		return fmt.Errorf("failed to glob rules: %w", err)
	}
	files = append(files, yamlFiles...)

	loadedCount := 0
	errorCount := 0

	for _, file := range files {
		rule, err := l.loadRuleFile(file)
		if err != nil {
			log.Printf("[WARN] Failed to load rule %s: %v", file, err)
			errorCount++
			continue
		}

		if !rule.IsValid() {
			log.Printf("[WARN] Invalid rule in %s: missing required fields", file)
			errorCount++
			continue
		}

		l.rules[rule.Name] = rule
		loadedCount++

		if l.onRuleLoaded != nil {
			l.onRuleLoaded(rule)
		}
	}

	log.Printf("[INFO] Loaded %d rules (%d errors) from %s", loadedCount, errorCount, l.rulesDir)
	return nil
}

// loadRuleFile loads a single YAML file
func (l *Loader) loadRuleFile(path string) (*Rule, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Set metadata
	rule.FilePath = path
	rule.LoadedAt = time.Now()

	info, err := os.Stat(path)
	if err == nil {
		rule.LastModified = info.ModTime()
	}

	// Default enabled to true if not specified
	if !rule.Enabled && rule.Enabled == false {
		// Check if enabled field was explicitly set
		var raw map[string]interface{}
		yaml.Unmarshal(data, &raw)
		if _, exists := raw["enabled"]; !exists {
			rule.Enabled = true
		}
	}

	return &rule, nil
}

// StartWatching enables hot-reload by watching rules directory
func (l *Loader) StartWatching() error {
	if err := l.watcher.Add(l.rulesDir); err != nil {
		return fmt.Errorf("failed to watch rules directory: %w", err)
	}

	go l.watchLoop()
	log.Printf("[INFO] Started watching rules directory: %s", l.rulesDir)
	return nil
}

// watchLoop handles file system events
func (l *Loader) watchLoop() {
	for {
		select {
		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}

			// Only handle YAML files
			if !strings.HasSuffix(event.Name, ".yaml") && !strings.HasSuffix(event.Name, ".yml") {
				continue
			}

			switch {
			case event.Op&fsnotify.Write == fsnotify.Write:
				// File modified
				l.handleFileModified(event.Name)
			case event.Op&fsnotify.Create == fsnotify.Create:
				// File created
				l.handleFileCreated(event.Name)
			case event.Op&fsnotify.Remove == fsnotify.Remove:
				// File deleted
				l.handleFileDeleted(event.Name)
			}

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[ERROR] Rule watcher error: %v", err)

		case <-l.stopCh:
			return
		}
	}
}

func (l *Loader) handleFileModified(path string) {
	log.Printf("[INFO] Rule file modified: %s", filepath.Base(path))

	newRule, err := l.loadRuleFile(path)
	if err != nil {
		log.Printf("[ERROR] Failed to reload rule: %v", err)
		return
	}

	if !newRule.IsValid() {
		log.Printf("[ERROR] Invalid rule after reload: %s", path)
		return
	}

	l.mu.Lock()
	oldRule := l.rules[newRule.Name]
	l.rules[newRule.Name] = newRule
	l.mu.Unlock()

	if l.onRuleUpdated != nil && oldRule != nil {
		l.onRuleUpdated(oldRule, newRule)
	} else if l.onRuleLoaded != nil {
		l.onRuleLoaded(newRule)
	}

	log.Printf("[INFO] Rule reloaded: %s", newRule.Name)
}

func (l *Loader) handleFileCreated(path string) {
	log.Printf("[INFO] New rule file detected: %s", filepath.Base(path))

	// Small delay to ensure file is fully written
	time.Sleep(100 * time.Millisecond)

	newRule, err := l.loadRuleFile(path)
	if err != nil {
		log.Printf("[ERROR] Failed to load new rule: %v", err)
		return
	}

	if !newRule.IsValid() {
		log.Printf("[ERROR] Invalid new rule: %s", path)
		return
	}

	l.mu.Lock()
	l.rules[newRule.Name] = newRule
	l.mu.Unlock()

	if l.onRuleLoaded != nil {
		l.onRuleLoaded(newRule)
	}

	log.Printf("[INFO] New rule loaded: %s", newRule.Name)
}

func (l *Loader) handleFileDeleted(path string) {
	log.Printf("[INFO] Rule file deleted: %s", filepath.Base(path))

	// Find rule by file path
	l.mu.Lock()
	var deletedRule *Rule
	for name, rule := range l.rules {
		if rule.FilePath == path {
			deletedRule = rule
			delete(l.rules, name)
			break
		}
	}
	l.mu.Unlock()

	if deletedRule != nil && l.onRuleUnloaded != nil {
		l.onRuleUnloaded(deletedRule.Name)
		log.Printf("[INFO] Rule unloaded: %s", deletedRule.Name)
	}
}

// GetRule returns a rule by name
func (l *Loader) GetRule(name string) (*Rule, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	rule, ok := l.rules[name]
	return rule, ok
}

// GetAllRules returns all loaded rules
func (l *Loader) GetAllRules() []*Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	rules := make([]*Rule, 0, len(l.rules))
	for _, rule := range l.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRuleSet returns metadata about loaded rules
func (l *Loader) GetRuleSet() *RuleSet {
	l.mu.RLock()
	defer l.mu.RUnlock()

	categories := make(map[string]int)
	enabledCount := 0

	for _, rule := range l.rules {
		categories[rule.Category]++
		if rule.Enabled {
			enabledCount++
		}
	}

	return &RuleSet{
		Rules:        l.GetAllRules(),
		LoadedAt:     time.Now(),
		RulesDir:     l.rulesDir,
		TotalRules:   len(l.rules),
		EnabledRules: enabledCount,
		Categories:   categories,
	}
}

// SetCallbacks sets event callbacks
func (l *Loader) SetCallbacks(
	onLoaded func(*Rule),
	onUnloaded func(string),
	onUpdated func(*Rule, *Rule),
) {
	l.onRuleLoaded = onLoaded
	l.onRuleUnloaded = onUnloaded
	l.onRuleUpdated = onUpdated
}

// Stop stops the file watcher
func (l *Loader) Stop() error {
	close(l.stopCh)
	return l.watcher.Close()
}
