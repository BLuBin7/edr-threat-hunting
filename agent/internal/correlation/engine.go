package correlation

import (
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/binhbl/edr-threat-hunting/agent/internal/monitors"
	// log "github.com/sirupsen/logrus"
)

// Engine performs behavioral correlation on telemetry events
// Uses sliding window to maintain temporal context without unbounded memory growth
type Engine struct {
	// Configuration
	windowSize  time.Duration
	maxMemoryMB int64

	// State storage (in-memory sliding window)
	processTree   map[int]*ProcessNode      // PID -> ProcessNode
	eventWindow   []monitors.Event          // Ring buffer of recent events
	attackChains  map[string]*AttackChain   // Attack chain tracking

	// Metrics
	startTime     time.Time
	eventsTotal   uint64
	chainsDetected uint64

	mu sync.RWMutex
}

// ProcessNode represents a process in the process tree
type ProcessNode struct {
	PID             int
	PPID            int
	ProcessName     string
	Commandline     string
	ExecutablePath  string
	Username        string
	IsElevated      bool
	StartTime       time.Time
	Children        []*ProcessNode
	Parent          *ProcessNode

	// Behavioral features
	FileOps         []FileOperation
	NetConnections  []NetworkConnection
	PersistenceOps  []PersistenceOperation

	// Rarity scoring
	IsRareProcess   bool
	RarityScore     float32
}

type FileOperation struct {
	Path        string
	Operation   string
	Timestamp   time.Time
	IsSensitive bool
}

type NetworkConnection struct {
	RemoteAddr  string
	RemotePort  int
	Protocol    string
	Timestamp   time.Time
	DNSQuery    string
}

type PersistenceOperation struct {
	Type      string
	Path      string
	Timestamp time.Time
}

// AttackChain represents a correlated sequence of suspicious behaviors
type AttackChain struct {
	ID                   string
	StartTime            time.Time
	LastUpdate           time.Time

	// Process lineage
	ProcessChain         []*ProcessNode
	ProcessLineageDepth  int
	IsRareParentChild    bool
	HasPrivilegeEscalation bool

	// Commandline features
	CmdlineLength        int
	CmdlineEntropy       float32
	HasEncodedCmd        bool

	// File activity
	FileModificationCount     int
	SensitiveFileAccessCount  int
	MassFileActivityRate      float32

	// Network activity
	NetworkConnectionCount    int
	HasSuspiciousDNS          bool
	BeaconingScore            float32

	// Persistence activity
	HasPersistenceMechanism   bool
	CronJobCount              int
	ServiceCreationCount      int

	// MITRE ATT&CK mapping
	MitreTactics             []string
	MitreTechniques          []string
}

type EngineOption func(*Engine)

func WithWindowSize(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.windowSize = d
	}
}

func WithMaxMemory(mb int64) EngineOption {
	return func(e *Engine) {
		e.maxMemoryMB = mb
	}
}

func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		windowSize:   30 * time.Minute,
		maxMemoryMB:  100,
		processTree:  make(map[int]*ProcessNode),
		eventWindow:  make([]monitors.Event, 0, 10000),
		attackChains: make(map[string]*AttackChain),
		startTime:    time.Now(),
	}

	for _, opt := range opts {
		opt(e)
	}

	// Start background cleanup goroutine
	go e.cleanupLoop()

	return e
}

// AddEvent adds a new event to the correlation engine
func (e *Engine) AddEvent(event monitors.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.eventsTotal++

	// Add to event window (ring buffer)
	e.eventWindow = append(e.eventWindow, event)

	// Process event based on type
	switch event.Type {
	case monitors.EventTypeProcess:
		e.handleProcessEvent(event)
	case monitors.EventTypeFile:
		e.handleFileEvent(event)
	case monitors.EventTypeNetwork:
		e.handleNetworkEvent(event)
	case monitors.EventTypePersistence:
		e.handlePersistenceEvent(event)
	}

	// Check memory usage and cleanup if needed
	if e.eventsTotal%1000 == 0 {
		e.cleanupOldEvents()
	}
}

func (e *Engine) handleProcessEvent(event monitors.Event) {
	pid := event.Data["pid"].(int)
	ppid := event.Data["ppid"].(int)
	processName := event.Data["process_name"].(string)
	cmdline := event.Data["commandline"].(string)

	node := &ProcessNode{
		PID:            pid,
		PPID:           ppid,
		ProcessName:    processName,
		Commandline:    cmdline,
		ExecutablePath: event.Data["executable_path"].(string),
		Username:       event.Data["username"].(string),
		IsElevated:     event.Data["is_elevated"].(bool),
		StartTime:      event.Timestamp,
		Children:       make([]*ProcessNode, 0),
		FileOps:        make([]FileOperation, 0),
		NetConnections: make([]NetworkConnection, 0),
		PersistenceOps: make([]PersistenceOperation, 0),
	}

	// Calculate rarity score
	node.RarityScore = e.calculateProcessRarity(node)
	node.IsRareProcess = node.RarityScore > 0.7

	// Link to parent in process tree
	if parent, exists := e.processTree[ppid]; exists {
		node.Parent = parent
		parent.Children = append(parent.Children, node)
	}

	e.processTree[pid] = node
}

func (e *Engine) handleFileEvent(event monitors.Event) {
	pid := event.Data["pid"].(int)
	path := event.Data["path"].(string)
	operation := event.Data["operation"].(string)
	isSensitive := event.Data["is_sensitive"].(bool)

	fileOp := FileOperation{
		Path:        path,
		Operation:   operation,
		Timestamp:   event.Timestamp,
		IsSensitive: isSensitive,
	}

	if node, exists := e.processTree[pid]; exists {
		node.FileOps = append(node.FileOps, fileOp)
	}
}

func (e *Engine) handleNetworkEvent(event monitors.Event) {
	pid := event.Data["pid"].(int)
	remoteAddr := event.Data["remote_addr"].(string)
	remotePort := event.Data["remote_port"].(int)
	protocol := event.Data["protocol"].(string)

	netConn := NetworkConnection{
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
		Protocol:   protocol,
		Timestamp:  event.Timestamp,
	}

	if dnsQuery, ok := event.Data["dns_query"].(string); ok {
		netConn.DNSQuery = dnsQuery
	}

	if node, exists := e.processTree[pid]; exists {
		node.NetConnections = append(node.NetConnections, netConn)
	}
}

func (e *Engine) handlePersistenceEvent(event monitors.Event) {
	persistType := event.Data["type"].(string)
	path := event.Data["path"].(string)

	persistOp := PersistenceOperation{
		Type:      persistType,
		Path:      path,
		Timestamp: event.Timestamp,
	}

	// Attribute to process if PID is provided
	if pidVal, ok := event.Data["pid"]; ok {
		var pid int
		switch v := pidVal.(type) {
		case int:
			pid = v
		case float64:
			pid = int(v)
		}
		if node, exists := e.processTree[pid]; exists {
			node.PersistenceOps = append(node.PersistenceOps, persistOp)
		}
	}
}

// GetAttackChains returns suspicious behavior chains detected for this event
func (e *Engine) GetAttackChains(event monitors.Event) []AttackChain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	chains := make([]AttackChain, 0)

	// Only analyze process events for chain detection
	if event.Type != monitors.EventTypeProcess {
		return chains
	}

	pid := event.Data["pid"].(int)
	node, exists := e.processTree[pid]
	if !exists {
		return chains
	}

	// Build process lineage
	lineage := e.buildProcessLineage(node)
	if len(lineage) < 2 {
		return chains // Need at least 2 processes for a chain
	}

	// Check for suspicious patterns
	if e.isSuspiciousChain(lineage) {
		chain := e.buildAttackChain(lineage)
		chains = append(chains, *chain)

		e.chainsDetected++
	}

	return chains
}

func (e *Engine) buildProcessLineage(node *ProcessNode) []*ProcessNode {
	lineage := make([]*ProcessNode, 0)
	current := node

	// Walk up the process tree
	for current != nil && len(lineage) < 10 {
		lineage = append([]*ProcessNode{current}, lineage...)
		current = current.Parent
	}

	return lineage
}

func (e *Engine) isSuspiciousChain(lineage []*ProcessNode) bool {
	// Pattern 1: Script interpreter → suspicious child
	for i := 0; i < len(lineage)-1; i++ {
		parent := lineage[i]
		child := lineage[i+1]

		// bash/sh → curl/wget
		if isShell(parent.ProcessName) && isDownloader(child.ProcessName) {
			return true
		}

		// Office app → PowerShell/script
		if isOfficeApp(parent.ProcessName) && isScriptInterpreter(child.ProcessName) {
			return true
		}

		// Rare parent-child combination
		if parent.IsRareProcess && child.IsRareProcess {
			return true
		}

		// Privilege escalation detected
		if !parent.IsElevated && child.IsElevated {
			return true
		}

		// Encoded command detected
		if containsEncodedCommand(child.Commandline) {
			return true
		}
	}

	// Pattern 2: Mass file activity
	lastNode := lineage[len(lineage)-1]
	if len(lastNode.FileOps) > 50 {
		return true
	}

	// Pattern 3: Suspicious network + persistence
	if len(lastNode.NetConnections) > 0 && len(lastNode.PersistenceOps) > 0 {
		return true
	}

	// Pattern 4: Weak signals correlation (Mức Trung Bình)
	// If any node in the lineage has file operations or network connections, evaluate the chain
	for _, node := range lineage {
		if len(node.FileOps) > 0 || len(node.NetConnections) > 0 {
			return true
		}
	}

	return false
}

func (e *Engine) buildAttackChain(lineage []*ProcessNode) *AttackChain {
	chain := &AttackChain{
		ID:           generateChainID(lineage),
		StartTime:    lineage[0].StartTime,
		LastUpdate:   time.Now(),
		ProcessChain: lineage,
		ProcessLineageDepth: len(lineage),
		MitreTactics:        make([]string, 0),
		MitreTechniques:     make([]string, 0),
	}

	lastNode := lineage[len(lineage)-1]

	// Check for rare parent-child
	if len(lineage) >= 2 {
		chain.IsRareParentChild = lineage[len(lineage)-2].IsRareProcess
	}

	// Check privilege escalation
	for i := 0; i < len(lineage)-1; i++ {
		if !lineage[i].IsElevated && lineage[i+1].IsElevated {
			chain.HasPrivilegeEscalation = true
			chain.MitreTactics = append(chain.MitreTactics, "TA0004 - Privilege Escalation")
			break
		}
	}

	// Commandline features
	chain.CmdlineLength = len(lastNode.Commandline)
	chain.CmdlineEntropy = calculateEntropy(lastNode.Commandline)
	chain.HasEncodedCmd = containsEncodedCommand(lastNode.Commandline)

	if chain.HasEncodedCmd {
		chain.MitreTactics = append(chain.MitreTactics, "TA0002 - Execution")
		chain.MitreTechniques = append(chain.MitreTechniques, "T1059 - Command and Scripting Interpreter")
	}

	// File activity (aggregated across the lineage)
	var allFileOps []FileOperation
	for _, node := range lineage {
		allFileOps = append(allFileOps, node.FileOps...)
	}
	chain.FileModificationCount = len(allFileOps)
	for _, fileOp := range allFileOps {
		if fileOp.IsSensitive {
			chain.SensitiveFileAccessCount++
		}
	}

	if chain.SensitiveFileAccessCount > 0 {
		chain.MitreTactics = append(chain.MitreTactics, "TA0006 - Credential Access")
		chain.MitreTechniques = append(chain.MitreTechniques, "T1003 - OS Credential Dumping")
	}

	// Calculate mass file activity rate (files/minute)
	if len(allFileOps) > 0 {
		duration := time.Since(lineage[0].StartTime).Minutes()
		if duration > 0 {
			chain.MassFileActivityRate = float32(len(allFileOps)) / float32(duration)
		}
	}

	// Network activity (aggregated across the lineage)
	var allNetConns []NetworkConnection
	for _, node := range lineage {
		allNetConns = append(allNetConns, node.NetConnections...)
	}
	chain.NetworkConnectionCount = len(allNetConns)
	chain.BeaconingScore = e.calculateBeaconingScore(allNetConns)
	chain.HasSuspiciousDNS = e.hasSuspiciousDNS(allNetConns)

	if chain.NetworkConnectionCount > 0 {
		chain.MitreTactics = append(chain.MitreTactics, "TA0011 - Command and Control")
	}

	// Persistence activity (aggregated across the lineage)
	var allPersistOps []PersistenceOperation
	for _, node := range lineage {
		allPersistOps = append(allPersistOps, node.PersistenceOps...)
	}
	chain.HasPersistenceMechanism = len(allPersistOps) > 0
	for _, persistOp := range allPersistOps {
		if persistOp.Type == "cron" {
			chain.CronJobCount++
		} else if persistOp.Type == "systemd_service" {
			chain.ServiceCreationCount++
		}
	}

	if chain.HasPersistenceMechanism {
		chain.MitreTactics = append(chain.MitreTactics, "TA0003 - Persistence")
		chain.MitreTechniques = append(chain.MitreTechniques, "T1053 - Scheduled Task/Job")
	}

	return chain
}

func (e *Engine) calculateProcessRarity(node *ProcessNode) float32 {
	// Simplified rarity calculation
	// In production, would use baseline frequency from historical data

	score := float32(0.0)

	// Rare process names
	rareProcesses := []string{"mimikatz", "procdump", "psexec", "wce", "pwdump", "powershell"}
	for _, rare := range rareProcesses {
		if node.ProcessName == rare {
			score += 0.5
		}
	}

	// Living off the land binaries (LOLBins)
	lolbins := []string{"certutil", "bitsadmin", "regsvr32", "mshta", "rundll32"}
	for _, lolbin := range lolbins {
		if node.ProcessName == lolbin {
			score += 0.3
		}
	}

	// Elevated processes
	if node.IsElevated {
		score += 0.1
	}

	// Long commandline
	if len(node.Commandline) > 500 {
		score += 0.2
	}

	return min(score, 1.0)
}

func (e *Engine) calculateBeaconingScore(connections []NetworkConnection) float32 {
	if len(connections) < 3 {
		return 0.0
	}

	// Calculate interval variance between connections
	intervals := make([]float64, 0)
	for i := 1; i < len(connections); i++ {
		interval := connections[i].Timestamp.Sub(connections[i-1].Timestamp).Seconds()
		intervals = append(intervals, interval)
	}

	// Low variance = periodic beaconing = suspicious
	mean := 0.0
	for _, interval := range intervals {
		mean += interval
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		variance += math.Pow(interval-mean, 2)
	}
	variance /= float64(len(intervals))

	// Beaconing score: high score = low variance (periodic)
	if variance < 10.0 && mean > 0 {
		return 0.9
	} else if variance < 100.0 {
		return 0.5
	}

	return 0.0
}

func (e *Engine) hasSuspiciousDNS(connections []NetworkConnection) bool {
	suspiciousDomains := []string{".tk", ".ml", ".ga", "dyn.dns", "no-ip"}
	for _, conn := range connections {
		for _, suspicious := range suspiciousDomains {
			if len(conn.DNSQuery) > 0 && containsSubstring(conn.DNSQuery, suspicious) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		e.mu.Lock()
		e.cleanupOldEvents()
		e.mu.Unlock()
	}
}

func (e *Engine) cleanupOldEvents() {
	cutoff := time.Now().Add(-e.windowSize)

	// Remove old events from window
	kept := make([]monitors.Event, 0, len(e.eventWindow))
	for _, event := range e.eventWindow {
		if event.Timestamp.After(cutoff) {
			kept = append(kept, event)
		}
	}
	e.eventWindow = kept

	// Remove old process nodes
	for pid, node := range e.processTree {
		if node.StartTime.Before(cutoff) {
			delete(e.processTree, pid)
		}
	}

	// Remove old attack chains
	for id, chain := range e.attackChains {
		if chain.LastUpdate.Before(cutoff) {
			delete(e.attackChains, id)
		}
	}
}

func (e *Engine) MemoryUsageMB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Alloc / 1024 / 1024)
}

func (e *Engine) ChainCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.attackChains)
}

// Utility functions
func isShell(name string) bool {
	shells := []string{"bash", "sh", "zsh", "fish", "dash"}
	for _, shell := range shells {
		if name == shell {
			return true
		}
	}
	return false
}

func isDownloader(name string) bool {
	downloaders := []string{"curl", "wget", "aria2c", "fetch"}
	for _, dl := range downloaders {
		if name == dl {
			return true
		}
	}
	return false
}

func isOfficeApp(name string) bool {
	return containsSubstring(name, "word") || containsSubstring(name, "excel") ||
	       containsSubstring(name, "powerpoint") || containsSubstring(name, "libreoffice")
}

func isScriptInterpreter(name string) bool {
	interpreters := []string{"python", "python3", "perl", "ruby", "node", "powershell", "pwsh"}
	for _, interp := range interpreters {
		if name == interp {
			return true
		}
	}
	return false
}

func containsEncodedCommand(cmdline string) bool {
	encodedPatterns := []string{"base64", "-enc", "-e ", "frombase64", "::FromBase64String"}
	for _, pattern := range encodedPatterns {
		if containsSubstring(cmdline, pattern) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
	       (s == substr || len(s) >= len(substr) &&
	        func() bool {
	            for i := 0; i <= len(s)-len(substr); i++ {
	                if s[i:i+len(substr)] == substr {
	                    return true
	                }
	            }
	            return false
	        }())
}

func calculateEntropy(s string) float32 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return float32(entropy)
}

func generateChainID(lineage []*ProcessNode) string {
	if len(lineage) == 0 {
		return "unknown"
	}
	// Simple ID: combine PIDs
	id := ""
	for _, node := range lineage {
		if id != "" {
			id += "->"
		}
		id += node.ProcessName
	}
	return id
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
