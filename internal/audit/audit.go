// Package audit records security-relevant user actions.
package audit

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Logger writes audit entries. It never fails the parent operation.
type Logger struct {
	db *database.DB
}

// NewLogger creates an audit logger.
func NewLogger(db *database.DB) *Logger { return &Logger{db: db} }

// Log records an action. details may be nil.
func (l *Logger) Log(ctx context.Context, userID *uuid.UUID, action, resourceType, resourceID string, details any, ip string) {
	var raw json.RawMessage = []byte(`{}`)
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			raw = b
		}
	}
	_, _ = l.db.Exec(ctx,
		`INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, action, resourceType, resourceID, raw, ip)
}

// LogRequest is a convenience wrapper extracting the client IP.
// SECURITY: RemoteAddr only — X-Forwarded-For is spoofable and never trusted.
func (l *Logger) LogRequest(r *http.Request, userID *uuid.UUID, action, resourceType, resourceID string, details any) {
	ip := r.RemoteAddr
	l.Log(r.Context(), userID, action, resourceType, resourceID, details, ip)
}

// List returns recent audit entries, newest first.
func (l *Logger) List(ctx context.Context, limit int) ([]models.AuditLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := l.db.Query(ctx,
		`SELECT id, user_id, action, resource_type, resource_id, details, ip, created_at
		 FROM audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var a models.AuditLog
		if err := rows.Scan(&a.ID, &a.UserID, &a.Action, &a.ResourceType, &a.ResourceID, &a.Details, &a.IP, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
