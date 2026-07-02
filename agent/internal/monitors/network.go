package monitors

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// NetworkMonitor polls /proc/net/tcp and /proc/net/udp to detect connections
type NetworkMonitor struct {
	config           NetworkMonitorConfig
	seenConnections  map[string]time.Time
	pollInterval     time.Duration
}

type NetworkMonitorConfig struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	TrackDNS     bool          `yaml:"track_dns"`
}

func NewNetworkMonitor(config NetworkMonitorConfig) *NetworkMonitor {
	if config.PollInterval == 0 {
		config.PollInterval = 5 * time.Second
	}
	return &NetworkMonitor{
		config:          config,
		seenConnections: make(map[string]time.Time),
		pollInterval:    config.PollInterval,
	}
}

func (m *NetworkMonitor) Start(ctx context.Context, eventChan chan<- Event) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	log.Info("Network monitor polling started")

	for {
		select {
		case <-ctx.Done():
			log.Info("Network monitor stopped")
			return
		case <-ticker.C:
			m.pollConnections(eventChan, "tcp")
			m.pollConnections(eventChan, "udp")
			m.cleanupStaleConnections()
		}
	}
}

func (m *NetworkMonitor) pollConnections(eventChan chan<- Event, protocol string) {
	procPath := fmt.Sprintf("/proc/net/%s", protocol)
	file, err := os.Open(procPath)
	if err != nil {
		log.WithError(err).WithField("protocol", protocol).Warn("Failed to open proc net file")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		conn := m.parseNetLine(line, protocol)
		if conn == nil {
			continue
		}

		// Create unique connection ID
		connID := fmt.Sprintf("%s:%s:%d:%s:%d",
			protocol, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)

		// Skip if we've recently seen this connection (within 30 seconds)
		if lastSeen, exists := m.seenConnections[connID]; exists {
			if time.Since(lastSeen) < 30*time.Second {
				continue
			}
		}

		m.seenConnections[connID] = time.Now()

		// Try to find the process that owns this connection
		processName := m.findProcessForConnection(conn.LocalPort, protocol)

		event := Event{
			Type:      EventTypeNetwork,
			Timestamp: time.Now(),
			Hostname:  getHostname(),
			Data: map[string]interface{}{
				"local_addr":     conn.LocalAddr,
				"local_port":     conn.LocalPort,
				"remote_addr":    conn.RemoteAddr,
				"remote_port":    conn.RemotePort,
				"protocol":       protocol,
				"state":          conn.State,
				"process_name":   processName,
				"pid":            0, // TODO: implement
			},
		}

		eventChan <- event

		// Check for suspicious patterns
		if m.isSuspiciousConnection(conn) {
			log.WithFields(log.Fields{
				"remote_addr": conn.RemoteAddr,
				"remote_port": conn.RemotePort,
				"process":     processName,
			}).Warn("Suspicious network connection detected")
		}
	}
}

func (m *NetworkMonitor) parseNetLine(line string, protocol string) *NetworkEvent {
	// Parse /proc/net/tcp format:
	// sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil
	}

	localAddr := fields[1]
	remoteAddr := fields[2]
	state := fields[3]

	localIP, localPort := parseAddress(localAddr)
	remoteIP, remotePort := parseAddress(remoteAddr)

	// Skip local loopback connections
	if localIP == "127.0.0.1" && remoteIP == "127.0.0.1" {
		return nil
	}

	// Skip connections with no remote address (0.0.0.0:0)
	if remoteIP == "0.0.0.0" && remotePort == 0 {
		return nil
	}

	stateName := getTCPStateName(state)

	return &NetworkEvent{
		LocalAddr:  localIP,
		LocalPort:  localPort,
		RemoteAddr: remoteIP,
		RemotePort: remotePort,
		Protocol:   protocol,
		State:      stateName,
		Timestamp:  time.Now(),
	}
}

func parseAddress(hexAddr string) (string, int) {
	// Format: "0100007F:1F40" -> "127.0.0.1:8000"
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "0.0.0.0", 0
	}

	// Parse IP (little-endian hex)
	ipHex := parts[0]
	var ipBytes [4]byte
	for i := 0; i < 4; i++ {
		if len(ipHex) >= (i+1)*2 {
			b, _ := strconv.ParseUint(ipHex[i*2:(i+1)*2], 16, 8)
			ipBytes[3-i] = byte(b)
		}
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

	// Parse port
	portHex := parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 64)

	return ip, int(port)
}

func getTCPStateName(hexState string) string {
	stateMap := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}

	if name, ok := stateMap[strings.ToUpper(hexState)]; ok {
		return name
	}
	return "UNKNOWN"
}

func (m *NetworkMonitor) findProcessForConnection(localPort int, protocol string) string {
	// Search through /proc/[pid]/fd/ for socket inodes matching this connection
	// This is a simplified version - production would need to match socket inode
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		return "unknown"
	}

	for _, procDir := range procDirs {
		if !procDir.IsDir() {
			continue
		}
		pidStr := procDir.Name()
		_, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Read /proc/[pid]/comm for process name
		commPath := filepath.Join("/proc", pidStr, "comm")
		commData, err := ioutil.ReadFile(commPath)
		if err != nil {
			continue
		}
		processName := strings.TrimSpace(string(commData))

		// TODO: More accurate matching via socket inode
		// For now just return the first process found
		return processName
	}

	return "unknown"
}

func (m *NetworkMonitor) isSuspiciousConnection(conn *NetworkEvent) bool {
	// Check for connections to suspicious ports
	suspiciousPorts := []int{4444, 5555, 6666, 7777, 8888, 9999, 31337}
	for _, port := range suspiciousPorts {
		if conn.RemotePort == port {
			return true
		}
	}

	// Check for non-standard high ports
	if conn.RemotePort > 49152 && conn.State == "ESTABLISHED" {
		return true
	}

	return false
}

func (m *NetworkMonitor) cleanupStaleConnections() {
	// Remove connections not seen in the last 5 minutes
	cutoff := time.Now().Add(-5 * time.Minute)
	for connID, lastSeen := range m.seenConnections {
		if lastSeen.Before(cutoff) {
			delete(m.seenConnections, connID)
		}
	}
}
