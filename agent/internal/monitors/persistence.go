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

// PersistenceMonitor watches for persistence mechanism changes (cron, systemd, autorun)
type PersistenceMonitor struct {
	config  PersistenceMonitorConfig
	watcher *fsnotify.Watcher
}

type PersistenceMonitorConfig struct {
	WatchCron    bool `yaml:"watch_cron"`
	WatchSystemd bool `yaml:"watch_systemd"`
	WatchAutorun bool `yaml:"watch_autorun"`
}

func NewPersistenceMonitor(config PersistenceMonitorConfig) (*PersistenceMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Default: watch all
	if !config.WatchCron && !config.WatchSystemd && !config.WatchAutorun {
		config.WatchCron = true
		config.WatchSystemd = true
		config.WatchAutorun = true
	}

	return &PersistenceMonitor{
		config:  config,
		watcher: watcher,
	}, nil
}

func (m *PersistenceMonitor) Start(ctx context.Context, eventChan chan<- Event) {
	// Add watch paths for persistence mechanisms
	watchPaths := m.getPersistencePaths()
	for _, path := range watchPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := m.watcher.Add(path); err != nil {
			log.WithError(err).WithField("path", path).Warn("Failed to watch path")
		}
	}

	log.WithField("watch_count", len(m.watcher.WatchList())).Info("Persistence monitor started")

	for {
		select {
		case <-ctx.Done():
			m.watcher.Close()
			log.Info("Persistence monitor stopped")
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handlePersistenceEvent(event, eventChan)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.WithError(err).Warn("Persistence monitor error")
		}
	}
}

func (m *PersistenceMonitor) getPersistencePaths() []string {
	var paths []string

	if m.config.WatchCron {
		paths = append(paths,
			"/etc/cron.d",
			"/etc/cron.daily",
			"/etc/cron.hourly",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron",
			"/var/spool/cron/crontabs",
		)
	}

	if m.config.WatchSystemd {
		paths = append(paths,
			"/etc/systemd/system",
			"/lib/systemd/system",
			"/usr/lib/systemd/system",
		)
	}

	if m.config.WatchAutorun {
		paths = append(paths,
			"/etc/rc.local",
			"/etc/profile.d",
			"/etc/init.d",
		)

		// User-level autorun (expand home directories)
		// Note: This is simplified - production would need to discover all users
		if homeMatches, err := filepath.Glob("/home/*"); err == nil {
			for _, home := range homeMatches {
				paths = append(paths,
					filepath.Join(home, ".bashrc"),
					filepath.Join(home, ".bash_profile"),
					filepath.Join(home, ".profile"),
					filepath.Join(home, ".config/autostart"),
				)
			}
		}
	}

	return paths
}

func (m *PersistenceMonitor) handlePersistenceEvent(fsEvent fsnotify.Event, eventChan chan<- Event) {
	// Ignore chmod events (too noisy)
	if fsEvent.Op&fsnotify.Chmod == fsnotify.Chmod {
		return
	}

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
	default:
		return
	}

	// Determine persistence type
	persistenceType := m.determinePersistenceType(fsEvent.Name)

	event := Event{
		Type:      EventTypePersistence,
		Timestamp: time.Now(),
		Hostname:  getHostname(),
		Data: map[string]interface{}{
			"type":         persistenceType,
			"path":         fsEvent.Name,
			"name":         filepath.Base(fsEvent.Name),
			"operation":    operation,
			"is_scheduled": strings.Contains(fsEvent.Name, "cron") || strings.Contains(fsEvent.Name, "systemd"),
		},
	}

	eventChan <- event

	log.WithFields(log.Fields{
		"type":      persistenceType,
		"path":      fsEvent.Name,
		"operation": operation,
	}).Warn("Persistence mechanism changed")
}

func (m *PersistenceMonitor) determinePersistenceType(path string) string {
	switch {
	case strings.Contains(path, "cron"):
		return "cron"
	case strings.Contains(path, "systemd"):
		return "systemd_service"
	case strings.Contains(path, "rc.local"):
		return "rc_local"
	case strings.Contains(path, "profile") || strings.Contains(path, "bashrc"):
		return "shell_profile"
	case strings.Contains(path, "autostart"):
		return "autostart"
	case strings.Contains(path, "init.d"):
		return "init_script"
	default:
		return "unknown"
	}
}
