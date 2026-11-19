// Package models defines the shared domain types used across all WADJET
// modules. These types mirror the database schema and form the integration
// contract between backend modules and the JSON API.
//
// Ownership: Engineering Lead. Other modules must not invent parallel
// structs for these entities; extend these types instead.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ───────────────────────────────────────────── enums

// ProjectStatus values.
const (
	ProjectStatusActive   = "active"
	ProjectStatusArchived = "archived"
)

// AssetType values.
const (
	AssetTypeIPv4      = "ipv4"
	AssetTypeIPv6      = "ipv6"
	AssetTypeHostname  = "hostname"
	AssetTypeDomain    = "domain"
	AssetTypeServer    = "server"
	AssetTypeEndpoint  = "endpoint"
	AssetTypeWebApp    = "web_app"
	AssetTypeContainer = "container"
	AssetTypeOther     = "other"
)

// DiscoverySource values.
const (
	DiscoveryManual  = "manual"
	DiscoveryScanner = "scanner"
	DiscoveryImport  = "import"
)

// ScanSessionStatus values.
const (
	ScanStatusDraft               = "draft"
	ScanStatusQueued              = "queued"
	ScanStatusRunning             = "running"
	ScanStatusCompleted           = "completed"
	ScanStatusCompletedWithErrors = "completed_with_errors"
	ScanStatusFailed              = "failed"
	ScanStatusCancelled           = "cancelled"
)

// ScannerExecutionStatus values.
const (
	ExecStatusQueued    = "queued"
	ExecStatusRunning   = "running"
	ExecStatusCompleted = "completed"
	ExecStatusFailed    = "failed"
	ExecStatusCancelled = "cancelled"
)

// Severity values.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// FindingStatus values.
const (
	FindingStatusOpen          = "open"
	FindingStatusConfirmed     = "confirmed"
	FindingStatusRemediated    = "remediated"
	FindingStatusAcceptedRisk  = "accepted_risk"
	FindingStatusFalsePositive = "false_positive"
)

// ReportType values.
const (
	ReportTypeScan                 = "scan"
	ReportTypeFinding              = "finding"
	ReportTypeFindingsConsolidated = "findings_consolidated"
	ReportTypeFindingsZip          = "findings_zip"
)

// ReportStatus values.
const (
	ReportStatusPending    = "pending"
	ReportStatusGenerating = "generating"
	ReportStatusCompleted  = "completed"
	ReportStatusFailed     = "failed"
)

// ───────────────────────────────────────────── entities

// User is an authenticated account.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// Project is a security assessment scope.
type Project struct {
	ID           uuid.UUID       `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Status       string          `json:"status"`
	Tags         []string        `json:"tags"`
	Settings     json.RawMessage `json:"settings"`
	CreatedBy    *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	LastActivity *time.Time      `json:"last_activity_at,omitempty"`
}

// ProjectTarget is an authorized (or excluded) scan target.
type ProjectTarget struct {
	ID         uuid.UUID `json:"id"`
	ProjectID  uuid.UUID `json:"project_id"`
	Target     string    `json:"target"`
	TargetType string    `json:"target_type"`
	Excluded   bool      `json:"excluded"`
	Note       string    `json:"note"`
	CreatedAt  time.Time `json:"created_at"`
}

// Asset is a persistent inventory entry. Identity is the normalized dedup
// key (IP address text, or lowercased hostname/domain) unique per project.
type Asset struct {
	ID              uuid.UUID `json:"id"`
	ProjectID       uuid.UUID `json:"project_id"`
	Identity        string    `json:"identity"`
	AssetType       string    `json:"asset_type"`
	IP              *string   `json:"ip,omitempty"`
	IPv6            *string   `json:"ipv6,omitempty"`
	Hostname        *string   `json:"hostname,omitempty"`
	Domain          *string   `json:"domain,omitempty"`
	MAC             *string   `json:"mac,omitempty"`
	OSName          *string   `json:"os_name,omitempty"`
	OSAccuracy      *int      `json:"os_accuracy,omitempty"`
	Status          string    `json:"status"`
	DiscoverySource string    `json:"discovery_source"`
	Description     string    `json:"description"`
	Tags            []string  `json:"tags"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AssetObservation is an immutable historical observation of an asset.
type AssetObservation struct {
	ID                 uuid.UUID       `json:"id"`
	AssetID            uuid.UUID       `json:"asset_id"`
	ScanSessionID      *uuid.UUID      `json:"scan_session_id,omitempty"`
	ScannerExecutionID *uuid.UUID      `json:"scanner_execution_id,omitempty"`
	ObservationType    string          `json:"observation_type"`
	ObservedAt         time.Time       `json:"observed_at"`
	Raw                json.RawMessage `json:"raw"`
	Source             string          `json:"source"`
	CreatedAt          time.Time       `json:"created_at"`
}

// ScannerRecord is a registry entry describing an available scanning tool.
type ScannerRecord struct {
	ID            uuid.UUID       `json:"id"`
	Name          string          `json:"name"`
	DisplayName   string          `json:"display_name"`
	Description   string          `json:"description"`
	Version       string          `json:"version"`
	Executable    string          `json:"executable"`
	Adapter       string          `json:"adapter"`
	Enabled       bool            `json:"enabled"`
	AssetTypes    []string        `json:"asset_types"`
	Capabilities  []string        `json:"capabilities"`
	Manifest      json.RawMessage `json:"manifest"`
	Status        string          `json:"status"`
	StatusDetail  string          `json:"status_detail"`
	LastChecked   *time.Time      `json:"last_checked_at,omitempty"`
	Documentation string          `json:"documentation"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// ScannerConfiguration is a project-level override of a scanner's defaults.
type ScannerConfiguration struct {
	ID        uuid.UUID       `json:"id"`
	ProjectID uuid.UUID       `json:"project_id"`
	ScannerID uuid.UUID       `json:"scanner_id"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ScanProfile defines how an assessment is executed.
type ScanProfile struct {
	ID              uuid.UUID        `json:"id"`
	ProjectID       uuid.UUID        `json:"project_id"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	TargetSelection []string         `json:"target_selection"`
	ExcludedTargets []string         `json:"excluded_targets"`
	TimeoutSeconds  int              `json:"timeout_seconds"`
	ReportPrefs     json.RawMessage  `json:"report_prefs"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	Scanners        []ProfileScanner `json:"scanners,omitempty"`
}

// ProfileScanner binds a scanner and its configuration to a profile.
type ProfileScanner struct {
	ID        uuid.UUID       `json:"id"`
	ProfileID uuid.UUID       `json:"profile_id"`
	ScannerID uuid.UUID       `json:"scanner_id"`
	Scanner   string          `json:"scanner"` // denormalized scanner name
	Config    json.RawMessage `json:"config"`
	SortOrder int             `json:"sort_order"`
}

// ScanSession is one execution of a scan profile or ad-hoc configuration.
type ScanSession struct {
	ID              uuid.UUID          `json:"id"`
	ProjectID       uuid.UUID          `json:"project_id"`
	ProfileID       *uuid.UUID         `json:"profile_id,omitempty"`
	Name            string             `json:"name"`
	Status          string             `json:"status"`
	Targets         []string           `json:"targets"`
	ScannerNames    []string           `json:"scanner_names"`
	AssetsProcessed int                `json:"assets_processed"`
	FindingsCreated int                `json:"findings_created"`
	FindingsUpdated int                `json:"findings_updated"`
	Error           string             `json:"error"`
	StartedAt       *time.Time         `json:"started_at,omitempty"`
	FinishedAt      *time.Time         `json:"finished_at,omitempty"`
	DurationMS      *int64             `json:"duration_ms,omitempty"`
	CreatedBy       *uuid.UUID         `json:"created_by,omitempty"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
	Executions      []ScannerExecution `json:"executions,omitempty"`
}

// ScannerExecution tracks one scanner's participation in a session.
type ScannerExecution struct {
	ID             uuid.UUID       `json:"id"`
	SessionID      uuid.UUID       `json:"session_id"`
	ScannerName    string          `json:"scanner_name"`
	Status         string          `json:"status"`
	Config         json.RawMessage `json:"config"`
	Targets        []string        `json:"targets"`
	RawOutputPath  string          `json:"raw_output_path"`
	RawOutputBytes int64           `json:"raw_output_bytes"`
	AssetsObserved int             `json:"assets_observed"`
	FindingsFound  int             `json:"findings_found"`
	Error          string          `json:"error"`
	Log            string          `json:"log"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Finding is a normalized security issue, deduplicated per project+asset+fingerprint.
type Finding struct {
	ID               uuid.UUID       `json:"id"`
	ProjectID        uuid.UUID       `json:"project_id"`
	AssetID          uuid.UUID       `json:"asset_id"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	TechnicalDetails string          `json:"technical_details"`
	Evidence         string          `json:"evidence"`
	Scanner          string          `json:"scanner"`
	Port             *int            `json:"port,omitempty"`
	Protocol         *string         `json:"protocol,omitempty"`
	Service          *string         `json:"service,omitempty"`
	CVEs             []string        `json:"cves"`
	CVSSScore        *float64        `json:"cvss_score,omitempty"`
	Severity         string          `json:"severity"`
	Status           string          `json:"status"`
	Remediation      string          `json:"remediation"`
	References       json.RawMessage `json:"references"`
	Fingerprint      string          `json:"fingerprint"`
	FirstDetected    time.Time       `json:"first_detected"`
	LastDetected     time.Time       `json:"last_detected"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// FindingObservation preserves one detection event of a finding.
type FindingObservation struct {
	ID                 uuid.UUID       `json:"id"`
	FindingID          uuid.UUID       `json:"finding_id"`
	ScanSessionID      *uuid.UUID      `json:"scan_session_id,omitempty"`
	ScannerExecutionID *uuid.UUID      `json:"scanner_execution_id,omitempty"`
	ObservedAt         time.Time       `json:"observed_at"`
	StatusAtDetection  string          `json:"status_at_detection"`
	Raw                json.RawMessage `json:"raw"`
	CreatedAt          time.Time       `json:"created_at"`
}

// FindingStatusHistory records a finding status transition.
type FindingStatusHistory struct {
	ID         uuid.UUID  `json:"id"`
	FindingID  uuid.UUID  `json:"finding_id"`
	FromStatus string     `json:"from_status"`
	ToStatus   string     `json:"to_status"`
	ChangedBy  *uuid.UUID `json:"changed_by,omitempty"`
	Note       string     `json:"note"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Report is a persisted generated document.
type Report struct {
	ID          uuid.UUID  `json:"id"`
	ProjectID   uuid.UUID  `json:"project_id"`
	SessionID   *uuid.UUID `json:"session_id,omitempty"`
	FindingID   *uuid.UUID `json:"finding_id,omitempty"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	FilePath    string     `json:"file_path"`
	FileSize    int64      `json:"file_size"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// AuditLog is a tamper-evident record of a user action.
type AuditLog struct {
	ID           uuid.UUID       `json:"id"`
	UserID       *uuid.UUID      `json:"user_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Details      json.RawMessage `json:"details"`
	IP           string          `json:"ip"`
	CreatedAt    time.Time       `json:"created_at"`
}
