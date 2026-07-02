package monitors

import "time"

// EventType represents the type of telemetry event
type EventType int

const (
	EventTypeProcess EventType = iota
	EventTypeFile
	EventTypeNetwork
	EventTypePersistence
)

func (e EventType) String() string {
	switch e {
	case EventTypeProcess:
		return "process"
	case EventTypeFile:
		return "file"
	case EventTypeNetwork:
		return "network"
	case EventTypePersistence:
		return "persistence"
	default:
		return "unknown"
	}
}

// Event represents a telemetry event from any monitor
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Hostname  string                 `json:"hostname"`
	Data      map[string]interface{} `json:"data"`
}

// ProcessEvent represents a process execution event
type ProcessEvent struct {
	PID             int       `json:"pid"`
	PPID            int       `json:"ppid"`
	ProcessName     string    `json:"process_name"`
	Commandline     string    `json:"commandline"`
	Username        string    `json:"username"`
	Timestamp       time.Time `json:"timestamp"`
	IsElevated      bool      `json:"is_elevated"`
	ExecutablePath  string    `json:"executable_path"`
	WorkingDir      string    `json:"working_dir"`
}

// FileEvent represents a file modification event
type FileEvent struct {
	Path        string    `json:"path"`
	Operation   string    `json:"operation"` // create, modify, delete, rename
	PID         int       `json:"pid"`
	ProcessName string    `json:"process_name"`
	Timestamp   time.Time `json:"timestamp"`
	IsSensitive bool      `json:"is_sensitive"`
	Size        int64     `json:"size"`
}

// NetworkEvent represents a network connection event
type NetworkEvent struct {
	PID           int       `json:"pid"`
	ProcessName   string    `json:"process_name"`
	LocalAddr     string    `json:"local_addr"`
	LocalPort     int       `json:"local_port"`
	RemoteAddr    string    `json:"remote_addr"`
	RemotePort    int       `json:"remote_port"`
	Protocol      string    `json:"protocol"` // tcp, udp
	State         string    `json:"state"`    // ESTABLISHED, LISTEN, etc.
	Timestamp     time.Time `json:"timestamp"`
	DNSQuery      string    `json:"dns_query,omitempty"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
}

// PersistenceEvent represents a persistence mechanism event
type PersistenceEvent struct {
	Type        string    `json:"type"` // cron, systemd_service, autorun
	Name        string    `json:"name"`
	Command     string    `json:"command"`
	Path        string    `json:"path"`
	Timestamp   time.Time `json:"timestamp"`
	CreatedBy   string    `json:"created_by"`
	IsScheduled bool      `json:"is_scheduled"`
}
