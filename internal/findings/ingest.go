package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/assets"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

// Errors returned by the ingestion pipeline.
var (
	// ErrEmptyResult is returned when a nil ScanResult is handed to Ingest.
	ErrEmptyResult = errors.New("nil scan result")
	// ErrSessionNotFound means the scan session does not exist.
	ErrSessionNotFound = errors.New("scan session not found")
	// ErrExecutionMismatch means the execution id is not an execution of the
	// given session: results can never be attributed to another session.
	ErrExecutionMismatch = errors.New("scanner execution does not belong to this session")
)

// findingCols renders the finding columns. cvss_score is cast to float8 so it
// scans cleanly into the *float64 of models.Finding, and "references" is
// quoted because it is a reserved word.
const findingCols = `id, project_id, asset_id, title, description, technical_details, evidence, scanner,
	port, protocol, service, cves, cvss_score::float8 AS cvss_score, severity, status, remediation,
	"references", fingerprint, first_detected, last_detected, created_at, updated_at`

// Ingest is the ResultSink implementation: it folds one scanner execution's
// output into the inventory. Asset upserts, finding upserts, observation
// inserts and counter updates all run in ONE transaction, so a scanner result
// is never half-applied and a failure cannot leave findings without assets.
//
// # Detection and verification policy
//
// This is the rule the whole findings lifecycle is built around, and it is
// intentionally explicit:
//
//  1. A finding is identified by (project_id, asset_id, fingerprint). The
//     fingerprint covers normalised title, scanner, port and protocol only —
//     never identity (already the asset scope), never evidence or timestamps
//     (they vary between runs). See FindingFingerprint.
//  2. Re-detection NEVER changes an analyst's status. A finding that is
//     confirmed, accepted_risk or false_positive stays exactly where the
//     analyst left it: an analyst decision is not overridden by a scanner
//     repeating itself.
//  3. The one exception is a finding that was marked remediated and is
//     detected again. Remediated means "the assessor believes this is fixed";
//     a scanner reporting it again is evidence that it is not. Such a finding
//     is reopened to 'open' and a finding_status_history row records
//     "re-detected by scanner <name>", so the reopen is never silent and is
//     always attributable. Findings that stay remediated (no longer reported)
//     are untouched, and only the scanner can reopen: the reopen row carries
//     no changed_by user.
//  4. Every detection, new or repeated, appends one immutable
//     finding_observations row holding the complete FindingResult JSON,
//     evidence included. History is append-only and is the audit trail for
//     "what did the scanner actually say".
//  5. Content refresh is conservative: evidence and technical details follow
//     the latest evidence the scanner produced, the first-seen description and
//     title are kept, missing fields are filled in, and nothing that is known
//     is blanked out.
//  6. A finding whose asset identity was never observed is skipped with a
//     logged error instead of failing the whole result: one malformed entry
//     must not cost the platform every other finding of that execution.
//
// Counters: scan_sessions.findings_created/findings_updated/assets_processed
// are incremented by this call's summary, and scanner_executions.assets_observed
// / findings_found are assigned this call's totals. Row-level dedup guaranteed
// by the unique key is the source of truth; the counters are the progress view
// the SSE stream reports. Ingest is called once per execution by the
// orchestrator, and re-running it for the same execution never duplicates
// finding rows — only observation rows, which are an append-only history.
func (s *Service) Ingest(ctx context.Context, sessionID, executionID uuid.UUID, scannerName string, result *scanners.ScanResult) error {
	if result == nil {
		return ErrEmptyResult
	}
	projectID, err := s.sessionProject(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := s.checkExecution(ctx, sessionID, executionID); err != nil {
		return err
	}

	return s.db.InTx(ctx, func(tx pgx.Tx) error {
		assetsProcessed := 0
		for _, obs := range result.Assets {
			if _, _, err := s.assets.UpsertFromScanTx(ctx, tx, projectID, sessionID, executionID, scannerName, obs); err != nil {
				return fmt.Errorf("ingest asset %q: %w", obs.Identity, err)
			}
			assetsProcessed++
		}

		created, updated, skipped := 0, 0, 0
		for _, fr := range result.Findings {
			asset, err := s.assets.FindByProjectIdentityTx(ctx, tx, projectID, fr.Identity)
			if errors.Is(err, assets.ErrNotFound) {
				slog.Error("findings: dropping finding for an asset that was never observed",
					"title", fr.Title, "identity", fr.Identity, "scanner", scannerName,
					"session_id", sessionID.String(), "execution_id", executionID.String())
				skipped++
				continue
			}
			if err != nil {
				return fmt.Errorf("resolve asset %q: %w", fr.Identity, err)
			}

			fp := FindingFingerprintFor(fr, scannerName)
			finding, wasCreated, err := upsertFinding(ctx, tx, projectID, asset.ID, fp, fr, scannerName)
			if err != nil {
				return fmt.Errorf("upsert finding %q: %w", fr.Title, err)
			}
			if wasCreated {
				created++
			} else {
				updated++
			}

			raw, err := json.Marshal(fr)
			if err != nil {
				return fmt.Errorf("encode finding observation: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO finding_observations
				 (finding_id, scan_session_id, scanner_execution_id, status_at_detection, raw)
				 VALUES ($1, $2, $3, $4, $5)`,
				finding.ID, sessionID, nullableUUID(executionID), finding.Status, raw); err != nil {
				return fmt.Errorf("insert finding observation: %w", err)
			}
		}

		if err := updateCounters(ctx, tx, sessionID, executionID,
			assetsProcessed, created, updated, len(result.Findings)-skipped); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET last_activity_at = now() WHERE id = $1`, projectID); err != nil {
			return fmt.Errorf("touch project activity: %w", err)
		}
		return nil
	})
}

// upsertFinding inserts or refreshes one finding. It reports whether the row is
// new, which is what feeds scan_sessions.findings_created.
func upsertFinding(ctx context.Context, tx pgx.Tx, projectID, assetID uuid.UUID, fingerprint string,
	fr scanners.FindingResult, scannerName string) (*models.Finding, bool, error) {

	port, protocol := fr.Port, strings.TrimSpace(fr.Protocol)
	severity := normalizeSeverity(fr.Severity)
	refs := json.RawMessage(`[]`)
	if len(fr.References) > 0 {
		b, err := json.Marshal(fr.References)
		if err != nil {
			return nil, false, err
		}
		refs = b
	}
	cves := fr.CVEs
	if cves == nil {
		cves = []string{}
	}

	// Insert path: ON CONFLICT DO NOTHING keeps the unique key
	// (project_id, asset_id, fingerprint) authoritative under concurrency.
	finding, err := scanFinding(tx.QueryRow(ctx,
		`INSERT INTO findings
		 (project_id, asset_id, title, description, technical_details, evidence, scanner,
		  port, protocol, service, cves, cvss_score, severity, status, remediation, "references",
		  fingerprint, first_detected, last_detected, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'open',$14,$15,$16,now(),now(),now(),now())
		 ON CONFLICT (project_id, asset_id, fingerprint) DO NOTHING
		 RETURNING `+findingCols,
		projectID, assetID, fr.Title, fr.Description, fr.TechnicalDetails, evidenceText(fr), scannerName,
		port, nullableText(protocol), nullableText(fr.Service), cves, fr.CVSSScore, severity,
		fr.Remediation, refs, fingerprint))
	if err == nil {
		return &finding, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}

	// Update path: lock the row so two concurrent executions cannot interleave
	// a status reopen with a read of the previous state.
	existing, err := scanFinding(tx.QueryRow(ctx,
		`SELECT `+findingCols+` FROM findings
		  WHERE project_id = $1 AND asset_id = $2 AND fingerprint = $3
		  FOR UPDATE`, projectID, assetID, fingerprint))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, ErrNotFound
		}
		return nil, false, err
	}

	newEvidence := evidenceText(fr)
	evidenceChanged := newEvidence != "" && newEvidence != existing.Evidence
	reopened := existing.Status == models.FindingStatusRemediated

	// Every parameter is cast explicitly: PostgreSQL must be able to type each
	// one from the statement alone.
	updatedFinding, err := scanFinding(tx.QueryRow(ctx,
		`UPDATE findings SET
			last_detected     = now(),
			updated_at        = now(),
			severity          = $2::text,
			cvss_score        = COALESCE($3::float8, cvss_score),
			service           = COALESCE(service, $4::text),
			cves              = CASE WHEN cardinality($5::text[]) > 0 THEN $5::text[] ELSE cves END,
			remediation       = CASE WHEN $6::text <> '' THEN $6::text ELSE remediation END,
			"references"      = CASE WHEN $7::jsonb <> '[]'::jsonb THEN $7::jsonb ELSE "references" END,
			description       = CASE WHEN description = '' THEN $8::text ELSE description END,
			technical_details = CASE WHEN $9::text <> '' AND $10::boolean THEN $11::text ELSE technical_details END,
			evidence          = CASE WHEN $9::text <> '' AND $10::boolean THEN $9::text ELSE evidence END,
			status            = CASE WHEN $12::boolean THEN 'open' ELSE status END
		 WHERE id = $1
		 RETURNING `+findingCols,
		existing.ID, severity, fr.CVSSScore, nullableText(fr.Service), cves, fr.Remediation, refs,
		fr.Description, newEvidence, evidenceChanged, fr.TechnicalDetails, reopened))
	if err != nil {
		return nil, false, err
	}

	// Policy rule 3: re-detection reopens a remediated finding, visibly.
	if reopened {
		note := fmt.Sprintf("re-detected by scanner %s", scannerName)
		if _, err := tx.Exec(ctx,
			`INSERT INTO finding_status_history (finding_id, from_status, to_status, changed_by, note)
			 VALUES ($1, $2, $3, NULL, $4)`, existing.ID, existing.Status, models.FindingStatusOpen, note); err != nil {
			return nil, false, fmt.Errorf("record reopen: %w", err)
		}
		updatedFinding.Status = models.FindingStatusOpen
	}
	return &updatedFinding, false, nil
}

// evidenceText is the text kept on the finding row: the human-readable snippet
// when the scanner gave one, otherwise its output. The full evidence envelope
// is preserved verbatim in finding_observations.raw.
func evidenceText(fr scanners.FindingResult) string {
	if strings.TrimSpace(fr.Evidence.Snippet) != "" {
		return fr.Evidence.Snippet
	}
	return fr.Evidence.Output
}

func updateCounters(ctx context.Context, tx pgx.Tx, sessionID, executionID uuid.UUID,
	assetsProcessed, created, updated, findingsFound int) error {

	if _, err := tx.Exec(ctx,
		`UPDATE scan_sessions SET
			assets_processed = assets_processed + $2,
			findings_created = findings_created + $3,
			findings_updated = findings_updated + $4,
			updated_at = now()
		 WHERE id = $1`,
		sessionID, assetsProcessed, created, updated); err != nil {
		return fmt.Errorf("update session counters: %w", err)
	}
	if executionID != uuid.Nil {
		if _, err := tx.Exec(ctx,
			`UPDATE scanner_executions SET assets_observed = $2, findings_found = $3 WHERE id = $1`,
			executionID, assetsProcessed, findingsFound); err != nil {
			return fmt.Errorf("update execution counters: %w", err)
		}
	}
	return nil
}

func (s *Service) sessionProject(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT project_id FROM scan_sessions WHERE id = $1`, sessionID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrSessionNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return projectID, nil
}

func (s *Service) checkExecution(ctx context.Context, sessionID, executionID uuid.UUID) error {
	if executionID == uuid.Nil {
		return nil
	}
	var ok bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scanner_executions WHERE id = $1 AND session_id = $2)`,
		executionID, sessionID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrExecutionMismatch
	}
	return nil
}

// normalizeSeverity keeps an unexpected scanner rating from aborting the
// transaction against the CHECK constraint; unknown ratings degrade to 'info'
// rather than being invented upward.
func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow:
		return strings.ToLower(strings.TrimSpace(sev))
	default:
		return models.SeverityInfo
	}
}

func nullableText(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
