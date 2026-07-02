package monitors

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// ProcessMonitor monitors process execution events via /proc polling
// (Userspace alternative to eBPF when kernel module access is restricted)
type ProcessMonitor struct {
	config       ProcessMonitorConfig
	seenPIDs     map[int]bool
	pollInterval time.Duration
}

type ProcessMonitorConfig struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	TrackLineage bool          `yaml:"track_lineage"`
}

func NewProcessMonitor(config ProcessMonitorConfig) *ProcessMonitor {
	if config.PollInterval == 0 {
		config.PollInterval = 1 * time.Second
	}
	return &ProcessMonitor{
		config:       config,
		seenPIDs:     make(map[int]bool),
		pollInterval: config.PollInterval,
	}
}

func (m *ProcessMonitor) Start(ctx context.Context, eventChan chan<- Event) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	log.Info("Process monitor polling started")

	for {
		select {
		case <-ctx.Done():
			log.Info("Process monitor stopped")
			return
		case <-ticker.C:
			m.pollProcesses(eventChan)
		}
	}
}

func (m *ProcessMonitor) pollProcesses(eventChan chan<- Event) {
	// Read /proc to discover new processes
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		log.WithError(err).Warn("Failed to read /proc")
		return
	}

	currentPIDs := make(map[int]bool)

	for _, procDir := range procDirs {
		// Only process numeric directories (PIDs)
		if !procDir.IsDir() {
			continue
		}
		pidStr := procDir.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		currentPIDs[pid] = true

		// Skip if we've already seen this PID
		if m.seenPIDs[pid] {
			continue
		}

		// New process detected - gather telemetry
		processEvent := m.gatherProcessInfo(pid)
		if processEvent != nil {
			m.seenPIDs[pid] = true

			event := Event{
				Type:      EventTypeProcess,
				Timestamp: time.Now(),
				Hostname:  getHostname(),
				Data: map[string]interface{}{
					"pid":             processEvent.PID,
					"ppid":            processEvent.PPID,
					"process_name":    processEvent.ProcessName,
					"commandline":     processEvent.Commandline,
					"username":        processEvent.Username,
					"is_elevated":     processEvent.IsElevated,
					"executable_path": processEvent.ExecutablePath,
					"working_dir":     processEvent.WorkingDir,
				},
			}
			eventChan <- event
		}
	}

	// Cleanup terminated PIDs from seenPIDs map
	for pid := range m.seenPIDs {
		if !currentPIDs[pid] {
			delete(m.seenPIDs, pid)
		}
	}
}

func (m *ProcessMonitor) gatherProcessInfo(pid int) *ProcessEvent {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/[pid]/stat for PPID
	statData, err := ioutil.ReadFile(filepath.Join(procPath, "stat"))
	if err != nil {
		return nil // Process may have terminated
	}

	statFields := strings.Fields(string(statData))
	if len(statFields) < 4 {
		return nil
	}

	ppid, _ := strconv.Atoi(statFields[3])

	// Read /proc/[pid]/cmdline
	cmdlineData, err := ioutil.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return nil
	}
	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	// Read /proc/[pid]/exe (executable path)
	exePath, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		exePath = "unknown"
	}

	// Read /proc/[pid]/cwd (working directory)
	cwd, err := os.Readlink(filepath.Join(procPath, "cwd"))
	if err != nil {
		cwd = "unknown"
	}

	// Get process owner (username)
	statusData, err := ioutil.ReadFile(filepath.Join(procPath, "status"))
	username := "unknown"
	isElevated := false
	if err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid, _ := strconv.Atoi(fields[1])
					if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
						username = u.Username
					}
					if uid == 0 {
						isElevated = true
					}
				}
				break
			}
		}
	}

	processName := filepath.Base(exePath)
	if processName == "unknown" && cmdline != "" {
		processName = strings.Fields(cmdline)[0]
	}

	return &ProcessEvent{
		PID:            pid,
		PPID:           ppid,
		ProcessName:    processName,
		Commandline:    cmdline,
		Username:       username,
		Timestamp:      time.Now(),
		IsElevated:     isElevated,
		ExecutablePath: exePath,
		WorkingDir:     cwd,
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
