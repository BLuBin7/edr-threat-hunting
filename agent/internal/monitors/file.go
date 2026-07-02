package monitors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

// FileMonitor watches sensitive file paths using inotify (via fsnotify)
type FileMonitor struct {
	config        FileMonitorConfig
	watcher       *fsnotify.Watcher
	sensitivePaths map[string]bool
}

type FileMonitorConfig struct {
	WatchPaths []string `yaml:"watch_paths"`
	Recursive  bool     `yaml:"recursive"`
}

func NewFileMonitor(config FileMonitorConfig) (*FileMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Default sensitive paths if not configured
	if len(config.WatchPaths) == 0 {
		config.WatchPaths = []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/root/.ssh",
			"/home/*/.ssh",
			"/etc/cron.d",
			"/var/spool/cron",
		}
	}

	sensitivePaths := make(map[string]bool)
	for _, path := range config.WatchPaths {
		sensitivePaths[path] = true
	}

	return &FileMonitor{
		config:        config,
		watcher:       watcher,
		sensitivePaths: sensitivePaths,
	}, nil
}

func (m *FileMonitor) Start(ctx context.Context, eventChan chan<- Event) {
	// Add watch paths
	for _, path := range m.config.WatchPaths {
		// Expand glob patterns
		matches, err := filepath.Glob(path)
		if err != nil {
			log.WithError(err).WithField("path", path).Warn("Failed to expand path")
			continue
		}

		for _, match := range matches {
			if err := m.addWatchRecursive(match); err != nil {
				log.WithError(err).WithField("path", match).Warn("Failed to add watch")
			}
		}
	}

	log.WithField("watch_count", len(m.watcher.WatchList())).Info("File monitor started")

	for {
		select {
		case <-ctx.Done():
			m.watcher.Close()
			log.Info("File monitor stopped")
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handleFileEvent(event, eventChan)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.WithError(err).Warn("File monitor error")
		}
	}
}

func (m *FileMonitor) addWatchRecursive(path string) error {
	err := m.watcher.Add(path)
	if err != nil {
		return err
	}

	if !m.config.Recursive {
		return nil
	}

	// If path is a directory and recursive is enabled, watch subdirectories
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil
	}

	return filepath.Walk(path, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return m.watcher.Add(walkPath)
		}
		return nil
	})
}

func (m *FileMonitor) handleFileEvent(fsEvent fsnotify.Event, eventChan chan<- Event) {
	operation := ""
	switch {
	case fsEvent.Op&fsnotify.Create == fsnotify.Create:
		operation = "create"
	case fsEvent.Op&fsnotify.Write == fsnotify.Write:
		operation = "modify"
	case fsEvent.Op&fsnotify.Remove == fsnotify.Remove:
		operation = "delete"
	case fsEvent.Op&fsnotify.Rename == fsnotify.Rename:
		operation = "rename"
	case fsEvent.Op&fsnotify.Chmod == fsnotify.Chmod:
		operation = "chmod"
	default:
		return
	}

	// Get file info
	var size int64
	if info, err := os.Stat(fsEvent.Name); err == nil {
		size = info.Size()
	}

	// Determine if file is in sensitive paths
	isSensitive := m.isSensitivePath(fsEvent.Name)

	// TODO: Get PID/process that modified the file
	// This requires additional tracking (e.g., fanotify or audit subsystem)
	// For now, we'll just log the event

	event := Event{
		Type:      EventTypeFile,
		Timestamp: time.Now(),
		Hostname:  getHostname(),
		Data: map[string]interface{}{
			"path":         fsEvent.Name,
			"operation":    operation,
			"is_sensitive": isSensitive,
			"size":         size,
			"pid":          0, // TODO: implement
			"process_name": "unknown",
		},
	}

	eventChan <- event

	if isSensitive {
		log.WithFields(log.Fields{
			"path":      fsEvent.Name,
			"operation": operation,
		}).Warn("Sensitive file modified")
	}
}

func (m *FileMonitor) isSensitivePath(path string) bool {
	// Check exact match
	if m.sensitivePaths[path] {
		return true
	}

	// Check if path is under any sensitive directory
	for sensitivePath := range m.sensitivePaths {
		if strings.HasPrefix(path, sensitivePath) {
			return true
		}
	}

	// Check common sensitive patterns
	sensitivePatterns := []string{
		".ssh/",
		"shadow",
		"passwd",
		"sudoers",
		"authorized_keys",
		"id_rsa",
		"id_ed25519",
		".pem",
		".key",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}
