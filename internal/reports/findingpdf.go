package reports

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/models"
)

// findingAdvisory renders a complete, customer-shareable standalone advisory
// for one finding, including the status history and detection timeline.
func (s *Service) findingAdvisory(ctx context.Context, findingID uuid.UUID) ([]byte, models.Finding, error) {
	f, err := loadFinding(ctx, s.db, findingID)
	if err != nil {
		return nil, models.Finding{}, err
	}
	project, err := loadProject(ctx, s.db, f.ProjectID)
	if err != nil {
		return nil, models.Finding{}, err
	}
	r := newRenderer(txt(project.Name), time.Now().UTC().Format("2006-01-02"))
	r.Cover(
		"Security Finding Advisory",
		fmt.Sprintf("%s — %s", f.Label(), title(f.Title)),
		[][2]string{
			{"Project", txt(project.Name)},
			{"Finding", f.Label()},
			{"Severity", strings.ToUpper(txt(f.Severity))},
			{"Asset", f.AssetText()},
			{"Generated", time.Now().UTC().Format("2006-01-02 15:04 MST")},
			{"Classification", "Confidential"},
		},
	)
	r.AddContentPage()
	renderFindingBody(r, f, true)
	b, _ := r.Bytes()
	return b, f.Finding, nil
}

// renderFindingBody renders the full detail block of one finding. full=true
// adds the extended advisory sections (status history, detections,
// business impact) used by standalone and consolidated reports.
func renderFindingBody(r *Renderer, f findingView, full bool) {
	r.pdf.Ln(2)
	// heading: label + title + severity chip
	r.pdf.SetFont("Helvetica", "B", 12)
	r.pdf.SetTextColor(15, 23, 42)
	r.pdf.SetXY(marginX, r.pdf.GetY())
	head := fmt.Sprintf("%s — %s", f.Label(), title(f.Title))
	r.pdf.MultiCell(contentW, 6, pdfText(head), "", "L", false)
	r.pdf.SetXY(marginX, r.pdf.GetY()+1)
	r.SeverityChip(f.Severity)
	if f.CVSSScore != nil {
		r.Chip(fmt.Sprintf("CVSS %.1f", *f.CVSSScore), clrSlate)
	}
	if st := strings.ToUpper(txt(f.Status)); st != "" {
		r.Chip("STATUS "+st, clrMuted)
	}
	r.pdf.SetXY(marginX, r.pdf.GetY()+7)

	facts := [][2]string{
		{"Asset", f.AssetText()},
		{"Asset type", dash(f.AssetType)},
		{"Port / service", f.PortText() + " · " + f.ServiceOrDash()},
		{"Scanner", dash(f.Scanner)},
		{"Fingerprint", txt(capText(f.Fingerprint, 128))},
		{"First detected", f.FirstDetected.Format("2006-01-02 15:04 MST")},
		{"Last detected", f.LastDetected.Format("2006-01-02 15:04 MST")},
	}
	r.KeyValues(facts)

	// CVE chips
	cves := make([]string, 0, len(f.CVEs))
	for _, c := range f.CVEs {
		if c = strings.ToUpper(collapseWhitespace(c)); strings.HasPrefix(c, "CVE-") {
			cves = append(cves, capText(c, 40))
		}
	}
	if len(cves) > 0 {
		r.Field("CVE IDENTIFIERS")
		r.ChipRow(cves, clrSlate)
	}

	if d := description(f.Description); d != "" {
		r.Field("DESCRIPTION")
		r.Para(d)
	}

	if td := technical(f.TechnicalDetails); td != "" {
		r.Field("TECHNICAL DETAILS")
		r.Para(td)
	}

	if ev := evidence(f.Evidence); strings.TrimSpace(ev) != "" {
		r.pdf.SetFont("Helvetica", "B", 9)
		r.pdf.SetTextColor(100, 116, 139)
		r.pdf.SetXY(marginX, r.pdf.GetY())
		r.Field("EVIDENCE (VERBATIM SCANNER OUTPUT)")
		r.MonoBlock(ev)
	}

	if rem := description(f.Remediation); rem != "" {
		r.Field("REMEDIATION")
		r.Para(rem)
	}

	if refs := f.ReferencesList(); len(refs) > 0 {
		r.Field("REFERENCES")
		for _, ref := range refs {
			r.pdf.SetFont("Courier", "", 8)
			r.pdf.SetTextColor(37, 99, 235)
			r.pdf.SetXY(marginX+2, r.pdf.GetY())
			r.pdf.MultiCell(contentW-2, 4.2, pdfText(ref), "", "L", false)
		}
		r.pdf.Ln(1.5)
	}

	if full {
		if bi := businessImpact(f); bi != "" {
			r.Field("BUSINESS IMPACT")
			r.Para(bi)
		}

		if len(f.StatusHistory) > 0 {
			r.Field("STATUS HISTORY")
			hist := make([][]string, 0, len(f.StatusHistory))
			for _, h := range f.StatusHistory {
				from := txt(h.FromStatus)
				if from == "" {
					from = "(new)"
				}
				note := txt(capText(collapseWhitespace(h.Note), 200))
				if note == "" {
					note = "—"
				}
				hist = append(hist, []string{h.CreatedAt.Format("2006-01-02 15:04"), from, txt(h.ToStatus), note})
			}
			r.Table([]string{"When", "From", "To", "Note"}, []float64{32, 32, 32, 78}, hist)
		}

		if len(f.Detections) > 0 {
			r.Field("OBSERVATION DATES")
			dets := make([][]string, 0, len(f.Detections))
			for _, d := range f.Detections {
				dets = append(dets, []string{d.ObservedAt.Format("2006-01-02 15:04 MST"), dash(d.Scanner), dash(d.Status)})
			}
			r.Table([]string{"Observed at", "Scanner", "Status at detection"}, []float64{58, 58, 58}, dets)
		}
	}

	// thin separator between findings
	r.pdf.SetDrawColor(226, 232, 240)
	r.pdf.SetLineWidth(0.3)
	r.pdf.Ln(2)
	r.pdf.Line(marginX, r.pdf.GetY(), marginX+contentW, r.pdf.GetY())
	r.pdf.Ln(3)
}

// businessImpact derives an impact statement from the severity plus the
// service context of a real finding. Returns "" for info severity with no
// service context.
func businessImpact(f findingView) string {
	sev := strings.ToLower(f.Severity)
	ctxPart := ""
	if f.ServiceOrDash() != "—" || f.Port != nil {
		ctxPart = fmt.Sprintf(" The issue is exposed on %s (%s).", f.PortText(), f.ServiceOrDash())
	} else if f.AssetIP != nil && *f.AssetIP != "" {
		ctxPart = fmt.Sprintf(" It affects the host %s.", *f.AssetIP)
	}
	switch sev {
	case models.SeverityCritical:
		return "Successful exploitation could lead to full compromise of the affected system or its data, " +
			"including remote code execution or unauthorized administrative access." + ctxPart +
			" Immediate remediation and incident review are recommended."
	case models.SeverityHigh:
		return "This issue materially weakens the security posture of the affected service and is readily " +
			"exploitable, potentially resulting in sensitive data exposure or privilege escalation." + ctxPart +
			" Remediation should be scheduled ahead of routine change work."
	case models.SeverityMedium:
		return "This issue increases the attack surface of the affected service and may be chained with other " +
			"weaknesses to achieve a more serious compromise." + ctxPart +
			" Remediation is recommended within the normal patching cycle."
	case models.SeverityLow:
		return "This is a minor weakness that alone is unlikely to lead to compromise but indicates a " +
			"hardening gap in the affected configuration." + ctxPart
	default: // info
		if ctxPart == "" {
			return ""
		}
		return "This is an informational observation. It does not represent a direct vulnerability, but the " +
			"disclosed detail can assist an attacker in reconnaissance." + ctxPart
	}
}

// consolidatedReport renders a single PDF covering many findings, preceded
// by a summary table of the included items.
func (s *Service) consolidatedReport(ctx context.Context, projectID uuid.UUID, flt findingFilter) ([]byte, error) {
	project, err := loadProject(ctx, s.db, projectID)
	if err != nil {
		return nil, err
	}
	findings, err := loadFindings(ctx, s.db, projectID, flt)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.ToLower(f.Severity)]++
	}

	r := newRenderer(txt(project.Name), time.Now().UTC().Format("2006-01-02"))
	r.Cover(
		"Consolidated Findings Report",
		fmt.Sprintf("%d finding(s) — %s", len(findings), scopeSummary(flt)),
		[][2]string{
			{"Project", txt(project.Name)},
			{"Findings", fmt.Sprintf("%d", len(findings))},
			{"Generated", time.Now().UTC().Format("2006-01-02 15:04 MST")},
			{"Classification", "Confidential"},
		},
	)

	r.AddContentPage()
	r.Section("Summary")
	total := len(findings)
	r.pdf.SetXY(marginX, r.pdf.GetY()+1)
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			r.Chip(fmt.Sprintf("%s · %d", strings.ToUpper(sev), counts[sev]), severityColors[sev])
		}
	}
	r.pdf.SetXY(marginX, r.pdf.GetY()+7)
	r.BarChart(counts, total)

	summaryRows := make([][]string, 0, total)
	for _, f := range findings {
		score := "—"
		if f.CVSSScore != nil {
			score = fmt.Sprintf("%.1f", *f.CVSSScore)
		}
		summaryRows = append(summaryRows, []string{
			f.Label(), title(f.Title), strings.ToUpper(txt(f.Severity)), score, f.AssetText(), f.PortText(),
		})
	}
	if len(summaryRows) == 0 {
		summaryRows = [][]string{{"— no findings match the requested scope —", "", "", "", "", ""}}
	}
	r.Table([]string{"ID", "Title", "Severity", "CVSS", "Asset", "Port"},
		[]float64{16, 62, 22, 14, 38, 22}, summaryRows)

	r.Section("Findings")
	if total == 0 {
		r.Para("No findings match the requested scope.")
	}
	for _, f := range findings {
		renderFindingBody(r, f, true)
	}

	b, _ := r.Bytes()
	return b, nil
}

func scopeSummary(flt findingFilter) string {
	parts := []string{}
	if len(flt.Severities) > 0 {
		parts = append(parts, "severities: "+strings.Join(flt.Severities, ", "))
	}
	if flt.AssetID != nil {
		parts = append(parts, "asset: "+flt.AssetID.String())
	}
	if flt.SessionID != nil {
		parts = append(parts, "session: "+flt.SessionID.String())
	}
	if len(parts) == 0 {
		return "all findings"
	}
	return strings.Join(parts, " · ")
}

// zipFinding is one rendered finding ready for ZIP packaging.
type zipFinding struct {
	Seq         int
	Title       string
	Severity    string
	Asset       string
	Fingerprint string
	PDF         []byte
}

// buildZip packages per-finding advisories plus a manifest.csv into a ZIP
// archive. Entry names are deterministic: findings/FND-<seq>-<slug>.pdf.
// Duplicate entry names get a numeric suffix. Pure function: no DB access,
// unit-testable with synthetic inputs.
func buildZip(items []zipFinding) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	seen := map[string]int{}

	// Deterministic manifest rows sorted by sequence.
	sorted := append([]zipFinding(nil), items...)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Seq < sorted[i].Seq {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	manifest := new(bytes.Buffer)
	cw := csv.NewWriter(manifest)
	if err := cw.Write([]string{"finding_id", "title", "severity", "asset", "fingerprint"}); err != nil {
		return nil, err
	}
	for _, it := range sorted {
		name := fmt.Sprintf("findings/FND-%d-%s.pdf", it.Seq, fileSafe(slugify(it.Title)))
		if n, dup := seen[name]; dup {
			seen[name] = n + 1
			name = fmt.Sprintf("findings/FND-%d-%s-%d.pdf", it.Seq, fileSafe(slugify(it.Title)), n+1)
		} else {
			seen[name] = 1
		}
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(it.PDF); err != nil {
			return nil, err
		}
		if err := cw.Write([]string{
			fmt.Sprintf("FND-%d", it.Seq),
			csvSafe(it.Title), csvSafe(it.Severity), csvSafe(it.Asset), csvSafe(it.Fingerprint),
		}); err != nil {
			return nil, err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return nil, err
	}
	mw, err := zw.Create("manifest.csv")
	if err != nil {
		return nil, err
	}
	if _, err := mw.Write(manifest.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// findingsZip renders a standalone advisory per finding and bundles them
// with manifest.csv into the standard WADJET export archive.
func (s *Service) findingsZip(ctx context.Context, projectID uuid.UUID, flt findingFilter) ([]byte, error) {
	findings, err := loadFindings(ctx, s.db, projectID, flt)
	if err != nil {
		return nil, err
	}
	items := make([]zipFinding, 0, len(findings))
	for _, f := range findings {
		pdf, err := s.findingPDFBytes(ctx, f)
		if err != nil {
			return nil, err
		}
		items = append(items, zipFinding{
			Seq:         f.Seq,
			Title:       title(f.Title),
			Severity:    txt(f.Severity),
			Asset:       collapseWhitespace(f.AssetIdentity),
			Fingerprint: txt(capText(f.Fingerprint, 128)),
			PDF:         pdf,
		})
	}
	return buildZip(items)
}

// findingPDFBytes renders a standalone advisory for an already-loaded
// finding (avoids re-querying when building ZIP archives).
func (s *Service) findingPDFBytes(ctx context.Context, f findingView) ([]byte, error) {
	project, err := loadProject(ctx, s.db, f.ProjectID)
	if err != nil {
		return nil, err
	}
	r := newRenderer(txt(project.Name), time.Now().UTC().Format("2006-01-02"))
	r.Cover(
		"Security Finding Advisory",
		fmt.Sprintf("%s — %s", f.Label(), title(f.Title)),
		[][2]string{
			{"Project", txt(project.Name)},
			{"Finding", f.Label()},
			{"Severity", strings.ToUpper(txt(f.Severity))},
			{"Asset", f.AssetText()},
			{"Generated", time.Now().UTC().Format("2006-01-02 15:04 MST")},
			{"Classification", "Confidential"},
		},
	)
	r.AddContentPage()
	// Load extended history for full advisories unless already attached
	// (ZIP path loads the full finding again to keep code simple and correct).
	full := f
	if len(full.Detections) == 0 {
		if fresh, err := loadFinding(ctx, s.db, f.ID); err == nil {
			full = fresh
		}
	}
	renderFindingBody(r, full, true)
	b, _ := r.Bytes()
	return b, nil
}
