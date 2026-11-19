package orchestration

import (
	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/events"
)

// SSE wire contract (docs/CONTRACTS.md §4). Topic is always "scan"; Kind and
// payload shape are binding.

// TopicScan is the bus topic for scan-related events.
const TopicScan = "scan"

// Event kinds.
const (
	KindScanStatus      = "scan.status"
	KindScanProgress    = "scan.progress"
	KindExecutionStatus = "execution.status"
)

// ScanStatusEvent is the scan.status payload.
type ScanStatusEvent struct {
	SessionID uuid.UUID `json:"session_id"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
}

// ScanProgressEvent is the scan.progress payload.
type ScanProgressEvent struct {
	SessionID       uuid.UUID `json:"session_id"`
	AssetsProcessed int       `json:"assets_processed"`
	FindingsCreated int       `json:"findings_created"`
	FindingsUpdated int       `json:"findings_updated"`
}

// ExecutionStatusEvent is the execution.status payload.
type ExecutionStatusEvent struct {
	SessionID      uuid.UUID `json:"session_id"`
	ExecutionID    uuid.UUID `json:"execution_id"`
	Scanner        string    `json:"scanner"`
	Status         string    `json:"status"`
	AssetsObserved int       `json:"assets_observed"`
	FindingsFound  int       `json:"findings_found"`
	Error          string    `json:"error,omitempty"`
}

// publish sends a scan-topic event; a nil bus disables publishing (tests).
func (o *Orchestrator) publish(kind string, payload any) {
	if o.bus == nil {
		return
	}
	o.bus.Publish(events.Event{Topic: TopicScan, Kind: kind, Payload: payload})
}
