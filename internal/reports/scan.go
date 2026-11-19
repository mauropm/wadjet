package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/models"
)

// scanData bundles everything a scan report renders from — all rows come
// from PostgreSQL, nothing is invented.
type scanData struct {
	Project    models.Project
	Session    models.ScanSession
	Execs      []executionView
	Assets     []assetView
	Findings   []findingView
	Scope      []scopeTarget
	ObsSummary []obsSummary
}

// renderScanReport renders the full assessment report for one scan session.
func (s *Service) renderScanReport(ctx context.Context, projectID, sessionID uuid.UUID) ([]byte, error) {
	d, err := s.loadScanData(ctx, projectID, sessionID)
	if err != nil {
		return nil, err
	}
	return renderScanReportBytes(d, time.Now().UTC()), nil
}

func (s *Service) loadScanData(ctx context.Context, projectID, sessionID uuid.UUID) (*scanData, error) {
	d := &scanData{}
	var err error
	if d.Project, err = loadProject(ctx, s.db, projectID); err != nil {
		return nil, fmt.Errorf("load project: %w", err)
	}
	if d.Session, err = loadSession(ctx, s.db, sessionID); err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	if d.Session.ProjectID != projectID {
		return nil, fmt.Errorf("%w: session does not belong to project", ErrNotFound)
	}
	if d.Execs, err = loadExecutions(ctx, s.db, sessionID); err != nil {
		return nil, err
	}
	if d.Assets, err = loadAssets(ctx, s.db, projectID, nil); err != nil {
		return nil, err
	}
	if d.Findings, err = loadFindings(ctx, s.db, projectID, findingFilter{SessionID: &sessionID}); err != nil {
		return nil, err
	}
	// If no finding observations reference the session (e.g. findings
	// predating observation tracking) fall back to the whole project so the
	// deliverable never silently omits known issues.
	if len(d.Findings) == 0 {
		if d.Findings, err = loadFindings(ctx, s.db, projectID, findingFilter{}); err != nil {
			return nil, err
		}
	}
	if d.Scope, err = loadScopeTargets(ctx, s.db, sessionID, projectID); err != nil {
		return nil, err
	}
	if d.ObsSummary, err = loadObservationSummary(ctx, s.db, projectID); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *scanData) severityCounts() (map[string]int, int) {
	counts := map[string]int{}
	total := 0
	for _, f := range d.Findings {
		sev := strings.ToLower(f.Severity)
		counts[sev]++
		total++
	}
	return counts, total
}

// narrative generates the executive summary paragraph from real statistics.
func (d *scanData) narrative(counts map[string]int, total int) string {
	var b strings.Builder
	targetN := len(d.Scope)
	fmt.Fprintf(&b, "WADJET assessed %s across %d target(s), %d asset(s) and %d scanner execution(s), identifying %d finding(s).",
		d.Project.Name, targetN, len(d.Assets), len(d.Execs), total)
	if total == 0 {
		b.WriteString(" No findings were recorded for this scope during the assessed period.")
		return b.String()
	}
	var parts []string
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	fmt.Fprintf(&b, " Severity distribution: %s.", strings.Join(parts, ", "))
	for _, sev := range severityOrder {
		if counts[sev] == 0 {
			continue
		}
		for _, f := range d.Findings {
			if strings.EqualFold(f.Severity, sev) {
				fmt.Fprintf(&b, " The highest-severity item, %s (“%s”), was observed on %s%s and requires prompt attention.",
					f.Label(), title(f.Title), f.AssetIdentity, serviceSuffix(f))
				break
			}
		}
		break
	}
	if counts["critical"]+counts["high"] > 0 {
		b.WriteString(" Remediation of critical and high findings should be prioritized before the next assessment cycle.")
	} else {
		b.WriteString(" No critical or high severity issues were identified in this scope.")
	}
	return b.String()
}

func serviceSuffix(f findingView) string {
	if f.Port == nil {
		return ""
	}
	return fmt.Sprintf(" port %s (%s)", f.PortText(), f.ServiceOrDash())
}

// renderScanReportBytes lays out the complete scan report.
func renderScanReportBytes(d *scanData, generatedAt time.Time) []byte {
	r := newRenderer(txt(d.Project.Name), generatedAt.Format("2006-01-02"))
	counts, total := d.severityCounts()

	sessionName := txt(d.Session.Name)
	if sessionName == "" {
		sessionName = "Session " + d.Session.ID.String()
	}

	// ── cover
	r.Cover(
		"Security Assessment Report",
		sessionName,
		[][2]string{
			{"Project", txt(d.Project.Name)},
			{"Scan session", sessionName},
			{"Session status", txt(d.Session.Status)},
			{"Generated", generatedAt.Format("2006-01-02 15:04 MST")},
			{"Report type", "Full scan report"},
			{"Classification", "Confidential"},
		},
	)

	// ── executive summary
	r.AddContentPage()
	r.Section("Executive Summary")
	// severity chip row with counts
	r.pdf.SetXY(marginX, r.pdf.GetY()+1)
	for _, sev := range severityOrder {
		c, ok := severityColors[sev]
		if !ok {
			continue
		}
		if counts[sev] > 0 {
			r.Chip(fmt.Sprintf("%s · %d", strings.ToUpper(sev), counts[sev]), c)
		}
	}
	r.pdf.SetXY(marginX, r.pdf.GetY()+7)
	r.Para(d.narrative(counts, total))
	r.KeyValues([][2]string{
		{"Findings", fmt.Sprintf("%d", total)},
		{"Assets", fmt.Sprintf("%d", len(d.Assets))},
		{"Targets", fmt.Sprintf("%d", len(d.Scope))},
		{"Scanner runs", fmt.Sprintf("%d", len(d.Execs))},
		{"Session started", fmtTime(d.Session.StartedAt)},
		{"Session finished", fmtTime(d.Session.FinishedAt)},
		{"Duration", fmtDuration(d.Session.DurationMS)},
	})

	// ── scope
	r.Section("Scope")
	if len(d.Session.Targets) > 0 {
		r.Para("The following targets were included when the scan session was started:")
		r.Table([]string{"Target", "Scanner target"}, []float64{100, 74},
			rowsOneCol(d.Session.Targets))
	}
	r.Para("Recorded scope entries (session targets and project scope, including exclusions):")
	scopeRows := make([][]string, 0, len(d.Scope))
	for _, t := range d.Scope {
		state := txt(t.Status)
		if t.Excluded {
			state = "excluded"
		}
		note := txt(t.Note)
		if t.Error != "" && !t.Excluded {
			note = collapseWhitespace(note + " " + t.Error)
		}
		scopeRows = append(scopeRows, []string{txt(t.Target), state, note})
	}
	if len(scopeRows) == 0 {
		scopeRows = [][]string{{"— no scope entries recorded —", "", ""}}
	}
	r.Table([]string{"Target", "State", "Note"}, []float64{78, 30, 66}, scopeRows)

	// ── methodology
	r.Section("Methodology")
	r.Para("WADJET executed the assessment through registered scanner adapters. Results were " +
		"ingested, normalized and deduplicated into the asset inventory and findings register; " +
		"this report renders exactly what is stored, with no synthetic content.")
	methRows := make([][]string, 0, len(d.Execs))
	for _, e := range d.Execs {
		ver := txt(e.Version)
		if ver == "" {
			ver = "—"
		}
		methRows = append(methRows, []string{txt(e.ScannerName), ver, txt(e.Status),
			compactJSON(e.Config, 300)})
	}
	if len(methRows) == 0 {
		names := make([][]string, 0, len(d.Session.ScannerNames))
		for _, n := range d.Session.ScannerNames {
			names = append(names, []string{txt(n), "—", "no execution recorded", "{}"})
		}
		if len(names) == 0 {
			names = [][]string{{"— no scanners configured —", "", "", ""}}
		}
		methRows = names
	}
	r.Table([]string{"Scanner", "Version", "Status", "Configuration summary"},
		[]float64{34, 22, 28, 90}, methRows)

	// ── asset inventory
	r.Section("Asset Inventory")
	assetRows := make([][]string, 0, len(d.Assets))
	for _, a := range d.Assets {
		os := "—"
		if a.OSName != nil && *a.OSName != "" {
			os = txt(*a.OSName)
			if a.OSAccuracy != nil {
				os += fmt.Sprintf(" (%d%%)", *a.OSAccuracy)
			}
		}
		assetRows = append(assetRows, []string{
			txt(a.Identity),
			deref(a.IP),
			deref(a.Hostname),
			os,
			fmt.Sprintf("%d", a.OpenPorts),
			a.FirstSeen.Format("2006-01-02 15:04"),
			a.LastSeen.Format("2006-01-02 15:04"),
		})
	}
	if len(assetRows) == 0 {
		assetRows = [][]string{{"— no assets recorded —", "", "", "", "", "", ""}}
	}
	r.Table([]string{"Identity", "IP", "Hostname", "Operating system", "Open ports", "First seen", "Last seen"},
		[]float64{36, 22, 30, 32, 14, 20, 20}, assetRows)

	// ── services & ports
	r.Section("Services & Ports")
	r.Para("Service data is taken from the most recent observation recorded for each asset " +
		"(raw scanner payload, normalized).")
	svcRows := make([][]string, 0)
	for _, a := range d.Assets {
		if len(a.Ports) == 0 {
			continue
		}
		ports := append([]observedPort(nil), a.Ports...)
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		for _, p := range ports {
			svcRows = append(svcRows, []string{
				txt(a.Identity), fmt.Sprintf("%d", p.Port), dash(p.Protocol), dash(p.Service),
				dash(p.State), txt(capText(p.Version, 160)),
			})
		}
	}
	if len(svcRows) == 0 {
		svcRows = [][]string{{"— no service observations recorded —", "", "", "", "", ""}}
	}
	r.Table([]string{"Asset", "Port", "Proto", "Service", "State", "Version"},
		[]float64{38, 12, 12, 26, 14, 72}, svcRows)

	// ── severity distribution
	r.Section("Severity Distribution")
	r.BarChart(counts, total)

	// ── detailed findings
	r.Section("Detailed Findings")
	if total == 0 {
		r.Para("No findings were recorded for this scan session.")
	} else {
		for _, sev := range severityOrder {
			group := make([]findingView, 0)
			for _, f := range d.Findings {
				if strings.EqualFold(f.Severity, sev) {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			r.SubSection(fmt.Sprintf("%s findings (%d)", strings.ToUpper(sev), len(group)))
			for _, f := range group {
				renderFindingBody(r, f, false)
			}
		}
	}

	// ── scan execution details
	r.Section("Scan Execution Details")
	exRows := make([][]string, 0, len(d.Execs))
	for _, e := range d.Execs {
		var dur string
		if e.StartedAt != nil {
			end := generatedAt
			if e.FinishedAt != nil {
				end = *e.FinishedAt
			}
			dur = (end.Sub(*e.StartedAt)).Round(time.Second).String()
		}
		raw := txt(e.RawOutputPath)
		if e.RawOutputBytes > 0 {
			raw = fmt.Sprintf("%s (%s)", raw, humanBytes(e.RawOutputBytes))
		}
		exRows = append(exRows, []string{
			txt(e.ScannerName), txt(e.Status), dash(dur),
			fmt.Sprintf("%d", e.AssetsObserved), fmt.Sprintf("%d", e.FindingsFound),
			capText(raw, 200),
		})
	}
	if len(exRows) == 0 {
		exRows = [][]string{{"— no executions recorded —", "", "", "", "", ""}}
	}
	r.Table([]string{"Scanner", "Status", "Duration", "Assets", "Findings", "Raw output"},
		[]float64{30, 24, 20, 14, 16, 70}, exRows)
	for _, e := range d.Execs {
		if txt(e.Error) != "" {
			r.Para("Execution error — " + txt(e.ScannerName) + ": " + txt(capText(e.Error, 600)))
		}
	}

	// ── appendix
	r.Section("Appendix — Observation Summary")
	obsRows := make([][]string, 0, len(d.ObsSummary))
	for _, o := range d.ObsSummary {
		obsRows = append(obsRows, []string{txt(o.Identity), txt(o.Type), fmt.Sprintf("%d", o.Count), o.LastAt.Format("2006-01-02 15:04")})
	}
	if len(obsRows) == 0 {
		obsRows = [][]string{{"— no observations recorded —", "", "", ""}}
	}
	r.Table([]string{"Asset", "Observation type", "Count", "Last observed"},
		[]float64{64, 44, 22, 44}, obsRows)

	b, _ := r.Bytes() // layout code cannot fail on valid geometry; errors also caught by gofpdf Err()
	return b
}

// ───────────────────────────────────────────── small layout helpers

func rowsOneCol(items []string) [][]string {
	out := make([][]string, 0, len(items))
	for _, it := range items {
		out = append(out, []string{txt(it), "scanner target"})
	}
	return out
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.Format("2006-01-02 15:04 MST")
}

func fmtDuration(ms *int64) string {
	if ms == nil || *ms < 0 {
		return "—"
	}
	return (time.Duration(*ms) * time.Millisecond).Round(time.Second).String()
}

func deref(s *string) string {
	if s == nil || *s == "" {
		return "—"
	}
	return txt(*s)
}

func dash(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return "—"
	}
	return txt(s)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// compactJSON renders raw JSONB on a single line, sanitized and capped.
func compactJSON(raw json.RawMessage, max int) string {
	if len(raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return txt(capText(string(raw), max))
	}
	return txt(capText(buf.String(), max))
}
