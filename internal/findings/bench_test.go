package findings

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets"
	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

// These benchmarks run only under `go test -bench`. They give the Lead a
// measured baseline for the two hot paths this package owns: the fingerprint
// (pure CPU, once per reported finding) and Ingest (the transactional write
// path the orchestrator calls once per scanner execution).
//
// Numbers depend on the local PostgreSQL instance, so they are a baseline for
// spotting regressions, not an SLA.

func BenchmarkFindingFingerprint(b *testing.B) {
	port := 443
	for i := 0; i < b.N; i++ {
		_ = FindingFingerprint("TLS Certificate Expires Soon", "nmap-nse", &port, "tcp")
	}
}

// BenchmarkIngest measures one execution's worth of results — assetsObserved
// assets with findingsPerAsset findings each — committed in a single
// transaction. Re-running it for the same execution also exercises the replay
// path, which replaces that execution's observations.
func BenchmarkIngest(b *testing.B) {
	const (
		assetsObserved   = 25
		findingsPerAsset = 8
	)
	ctx := context.Background()
	s := NewService(itest.DB(), assets.NewService(itest.DB()), nil)
	project := benchProject(b)
	session := benchSession(b, project)
	exec := benchExecution(b, session)

	result := &scanners.ScanResult{}
	for a := 0; a < assetsObserved; a++ {
		identity := "10.77." + strconv.Itoa(a/250) + "." + strconv.Itoa(a%250)
		result.Assets = append(result.Assets, scanners.AssetObservationData{
			Identity: identity,
			Ports: []scanners.PortObservation{
				{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
				{Port: 443, Protocol: "tcp", State: "open", Service: "https"},
			},
		})
		for f := 0; f < findingsPerAsset; f++ {
			p := 80 + f
			result.Findings = append(result.Findings, scanners.FindingResult{
				Title:            fmt.Sprintf("Benchmark finding %d", f),
				Description:      "benchmarked description",
				Identity:         identity,
				Port:             &p,
				Protocol:         "tcp",
				Severity:         models.SeverityMedium,
				Evidence:         scanners.FindingEvidence{Snippet: "benchmark evidence"},
				CVEs:             []string{"CVE-2024-0000"},
				References:       []string{"https://example.com/advisory"},
				Remediation:      "upgrade",
				Service:          "http",
				TechnicalDetails: "benchmark details",
			})
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Ingest(ctx, session, exec, "nmap", result); err != nil {
			b.Fatalf("ingest: %v", err)
		}
	}
	b.ReportMetric(float64(len(result.Findings)), "findings/op")
	b.ReportMetric(float64(len(result.Assets)), "assets/op")
}

// The itest seed helpers take *testing.T, so the benchmark needs its own
// *testing.B variants.

func benchProject(b *testing.B) uuid.UUID {
	b.Helper()
	var id uuid.UUID
	if err := itest.DB().QueryRow(context.Background(),
		`INSERT INTO projects (name, description, status, tags, settings, updated_at)
		 VALUES ($1, '', 'active', '{}', '{}'::jsonb, now()) RETURNING id`,
		"bench-"+b.Name()+"-"+uuid.NewString()[:8]).Scan(&id); err != nil {
		b.Fatalf("insert project: %v", err)
	}
	b.Cleanup(func() {
		_, _ = itest.DB().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, id)
	})
	return id
}

func benchSession(b *testing.B, project uuid.UUID) uuid.UUID {
	b.Helper()
	var id uuid.UUID
	if err := itest.DB().QueryRow(context.Background(),
		`INSERT INTO scan_sessions (project_id, name, status, updated_at)
		 VALUES ($1, $2, 'running', now()) RETURNING id`, project, "bench-session").Scan(&id); err != nil {
		b.Fatalf("insert session: %v", err)
	}
	return id
}

func benchExecution(b *testing.B, session uuid.UUID) uuid.UUID {
	b.Helper()
	var id uuid.UUID
	if err := itest.DB().QueryRow(context.Background(),
		`INSERT INTO scanner_executions (session_id, scanner_name, status)
		 VALUES ($1, 'nmap', 'running') RETURNING id`, session).Scan(&id); err != nil {
		b.Fatalf("insert execution: %v", err)
	}
	return id
}
