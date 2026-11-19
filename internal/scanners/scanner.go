// Package scanners defines the extensible scanner contracts.
//
// Ownership: Engineering Lead owns these contract types. The scanner engine
// (registry, adapters, parsers, orchestrator) implements them; the ingestion
// layer consumes them. New scanners implement Scanner without touching the
// orchestration engine.
package scanners

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Capability describes what a scanner can detect.
type Capability string

const (
	CapHostDiscovery    Capability = "host_discovery"
	CapPortDiscovery    Capability = "port_discovery"
	CapServiceDetection Capability = "service_detection"
	CapVersionDetection Capability = "version_detection"
	CapOODetection      Capability = "os_detection"
	CapVulnDetection    Capability = "vulnerability_detection"
	CapWebDiscovery     Capability = "web_discovery"
	CapTLSDetection     Capability = "tls_assessment"
)

// ScannerConfig is scanner-specific configuration. Option keys are defined
// by the scanner's manifest (e.g. "scripts": ["safe"], "os_detection": true).
type ScannerConfig map[string]any

// Target is an authorized scan target.
type Target struct {
	Raw       string // as configured, e.g. "10.0.0.0/24" or "example.com"
	Type      string // ip, ipv6, hostname, domain, cidr, url
	AssetID   *uuid.UUID
	ProjectID uuid.UUID
}

// ScanRequest is passed to a scanner execution.
type ScanRequest struct {
	SessionID   uuid.UUID
	ExecutionID uuid.UUID
	ProjectID   uuid.UUID
	Targets     []Target
	Config      ScannerConfig
	WorkDir     string // private working directory for this execution
	Timeout     time.Duration
}

// PortObservation is one observed network port.
type PortObservation struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // tcp, udp
	State     string `json:"state"`    // open, closed, filtered
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
}

// AssetObservationData is one asset's raw scanner observations. It is stored
// verbatim in asset_observations.raw for auditing.
type AssetObservationData struct {
	Identity   string            `json:"identity"` // ip or lowercased hostname
	IPv4       string            `json:"ipv4,omitempty"`
	IPv6       string            `json:"ipv6,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty"`
	OSName     string            `json:"os_name,omitempty"`
	OSAccuracy int               `json:"os_accuracy,omitempty"`
	Ports      []PortObservation `json:"ports,omitempty"`
	Extra      map[string]any    `json:"extra,omitempty"`
}

// FindingEvidence preserves raw scanner evidence behind a finding.
type FindingEvidence struct {
	Raw     json.RawMessage `json:"raw,omitempty"`
	Snippet string          `json:"snippet,omitempty"`
	Script  string          `json:"script,omitempty"` // e.g. NSE script id
	Output  string          `json:"output,omitempty"`
}

// FindingResult is one normalized finding reported by a scanner.
//
// Security rule: never fabricate CVEs or CVSS scores. Only populate them
// when the scanner output or trusted intelligence supports them.
type FindingResult struct {
	Title            string          `json:"title"`
	Description      string          `json:"description,omitempty"`
	TechnicalDetails string          `json:"technical_details,omitempty"`
	Evidence         FindingEvidence `json:"evidence"`
	Identity         string          `json:"identity"` // asset identity, matches AssetObservationData.Identity
	Port             *int            `json:"port,omitempty"`
	Protocol         string          `json:"protocol,omitempty"`
	Service          string          `json:"service,omitempty"`
	CVEs             []string        `json:"cves,omitempty"`
	CVSSScore        *float64        `json:"cvss_score,omitempty"`
	Severity         string          `json:"severity"` // critical, high, medium, low, info
	Remediation      string          `json:"remediation,omitempty"`
	References       []string        `json:"references,omitempty"`
}

// ScannerError records a non-fatal per-target failure.
type ScannerError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// ScanResult is the complete output of one scanner execution.
type ScanResult struct {
	Assets    []AssetObservationData `json:"assets"`
	Findings  []FindingResult        `json:"findings"`
	RawOutput []byte                 `json:"-"` // stored to disk, never rendered directly
	Errors    []ScannerError         `json:"errors,omitempty"`
}

// Scanner is implemented by every integrated security tool.
type Scanner interface {
	Name() string
	Version() string
	Description() string
	Capabilities() []Capability

	// ValidateConfig rejects configuration outside the scanner's manifest.
	ValidateConfig(config ScannerConfig) error
	// ValidateTarget rejects targets the scanner cannot handle.
	ValidateTarget(target Target) error

	// Execute runs the tool, blocking until completion or ctx cancellation.
	// It must never build shell strings; arguments are passed separately.
	Execute(ctx context.Context, request ScanRequest) (*ScanResult, error)
}

// ResultSink ingests normalized scan results. Implemented by the findings
// module; consumed by the orchestrator. Implementations must be idempotent
// and must never lose results when other scanners fail.
type ResultSink interface {
	Ingest(ctx context.Context, sessionID uuid.UUID, executionID uuid.UUID, scannerName string, result *ScanResult) error
}
