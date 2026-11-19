package reports

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

// Brand palette. Emerald is the WADJET accent; the severity colors match the
// frontend chips so printed and on-screen findings look identical.
var (
	clrEmerald = color.RGBA{16, 185, 129, 255}  // #10B981
	clrInk     = color.RGBA{15, 23, 42, 255}    // #0F172A
	clrSlate   = color.RGBA{71, 85, 105, 255}   // #475569
	clrMuted   = color.RGBA{100, 116, 139, 255} // #64748B
	clrRule    = color.RGBA{203, 213, 225, 255} // #CBD5E1
	clrZebra   = color.RGBA{248, 250, 252, 255} // #F8FAFC
	clrPanel   = color.RGBA{241, 245, 249, 255} // #F1F5F9
	clrWhite   = color.RGBA{255, 255, 255, 255}
)

// severityColors maps a severity value to its chip color.
var severityColors = map[string]color.RGBA{
	"critical": {239, 68, 68, 255},   // #EF4444
	"high":     {249, 115, 22, 255},  // #F97316
	"medium":   {234, 179, 8, 255},   // #EAB308
	"low":      {59, 130, 246, 255},  // #3B82F6
	"info":     {100, 116, 139, 255}, // #64748B
}

// severityOrder controls display order everywhere in a report.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// Page geometry (mm, A4 portrait).
const (
	pageW      = 210.0
	pageH      = 297.0
	marginX    = 18.0
	headerY    = 12.0
	contentTop = 24.0
	footerY    = 284.0
	contentW   = pageW - 2*marginX // 174
)

// Renderer wraps a gofpdf document with WADJET branding: cover page with the
// geometric eye mark, per-page header ("WADJET · project · date") and footer
// ("Page N of M"), and layout primitives (sections, tables, chips, bar
// charts, monospace evidence blocks). All text passed to its methods is
// treated as untrusted and goes through pdfText.
type Renderer struct {
	pdf     *gofpdf.Fpdf
	project string
	date    string
}

// newRenderer builds an empty branded document. The caller adds a cover via
// Cover() then content pages via AddContentPage()/Section().
func newRenderer(project, date string) *Renderer {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(marginX, contentTop, marginX)
	pdf.SetAutoPageBreak(true, pageH-footerY+4)
	pdf.SetCompression(true)
	pdf.SetCreator("WADJET", false)
	pdf.SetTitle("WADJET Security Report", true)
	pdf.SetSubject("Automated security assessment deliverable", true)

	r := &Renderer{pdf: pdf, project: project, date: date}
	pdf.SetHeaderFunc(func() {
		if pdf.PageNo() <= 1 { // cover page carries its own branding
			return
		}
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetTextColor(100, 116, 139)
		pdf.SetXY(marginX, headerY)
		pdf.CellFormat(contentW, 4, pdfText("WADJET · "+r.project+" · "+r.date), "", 0, "L", false, 0, "")
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFillColor(16, 185, 129)
		pdf.Rect(marginX, headerY+5.2, 30, 0.6, "F")
		pdf.SetFillColor(203, 213, 225)
		pdf.Rect(marginX+30, headerY+5.2, contentW-30, 0.6, "F")
	})
	pdf.SetFooterFunc(func() {
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(148, 163, 184)
		pdf.SetXY(marginX, footerY)
		pdf.CellFormat(contentW*0.7, 4, pdfText("WADJET · We see what your assets are hiding."), "", 0, "L", false, 0, "")
		pdf.SetXY(marginX+contentW*0.3, footerY)
		pdf.CellFormat(contentW*0.3, 4, "Page "+strconv.Itoa(pdf.PageNo())+" of {nb}", "", 0, "R", false, 0, "")
		pdf.SetTextColor(255, 255, 255)
	})
	pdf.AliasNbPages("{nb}")
	return r
}

// AddContentPage starts a new page (with header/footer applied).
func (r *Renderer) AddContentPage() { r.pdf.AddPage() }

// Bytes renders the document into memory.
func (r *Renderer) Bytes() ([]byte, error) {
	var b strings.Builder
	if err := r.pdf.Output(&b); err != nil {
		return nil, err
	}
	if r.pdf.Err() {
		return nil, r.pdf.Error()
	}
	return []byte(b.String()), nil
}

// ───────────────────────────────────────────── cover page

// Cover draws page 1: emerald band, the geometric eye mark, the WADJET
// wordmark and tagline, a title block and document metadata.
func (r *Renderer) Cover(docTitle, subtitle string, meta [][2]string) {
	r.pdf.AddPage()
	// Top and bottom accent bands.
	r.fill(clrEmerald, 0, 0, pageW, 5)
	r.fill(clrEmerald, 0, pageH-5, pageW, 5)

	// ── geometric eye mark: lids (arcs), iris, pupil, highlight, tail.
	cx, cy := pageW/2, 58.0
	r.pdf.SetDrawColor(16, 185, 129)
	r.pdf.SetLineWidth(1.4)
	// upper and lower lid arcs forming the almond outline
	r.pdf.Arc(cx, cy, 40, 17, 0, 180, 360, "D")
	r.pdf.Arc(cx, cy, 40, 17, 0, 0, 180, "D")
	// iris + pupil + highlight
	r.drawCircle(cx, cy, 13, clrEmerald)
	r.drawCircle(cx, cy, 5.6, clrWhite)
	r.drawCircle(cx-2.4, cy-2.4, 1.7, clrEmerald)
	// brow line
	r.pdf.SetLineWidth(0.9)
	r.pdf.Line(cx-34, cy-24, cx+34, cy-24)
	// tail sweeping out of the outer corner (abstract feather lash)
	r.pdf.SetLineWidth(1.6)
	r.pdf.CurveBezierCubic(cx+38, cy-2, cx+56, cy-2, cx+60, cy+8, cx+64, cy+20, "D")
	r.pdf.SetLineWidth(0.7)
	r.pdf.CurveBezierCubic(cx+34, cy+7, cx+50, cy+9, cx+52, cy+13, cx+55, cy+21, "D")

	// ── wordmark + tagline
	r.pdf.SetTextColor(15, 23, 42)
	r.pdf.SetFont("Helvetica", "B", 30)
	r.pdf.SetXY(marginX, 96)
	r.pdf.CellFormat(contentW, 14, "W A D J E T", "", 1, "C", false, 0, "")
	r.pdf.SetFont("Helvetica", "I", 11.5)
	r.pdf.SetTextColor(100, 116, 139)
	r.pdf.SetXY(marginX, 111)
	r.pdf.CellFormat(contentW, 7, "We see what your assets are hiding.", "", 1, "C", false, 0, "")

	// ── document title block
	blockY := 134.0
	r.fill(clrEmerald, marginX, blockY, contentW, 1.6)
	r.pdf.SetFont("Helvetica", "B", 17)
	r.pdf.SetTextColor(15, 23, 42)
	r.pdf.SetXY(marginX, blockY+6)
	r.pdf.MultiCell(contentW, 8.5, pdfText(docTitle), "", "C", false)
	if subtitle != "" {
		r.pdf.SetFont("Helvetica", "", 10.5)
		r.pdf.SetTextColor(71, 85, 105)
		r.pdf.SetXY(marginX, r.pdf.GetY()+2)
		r.pdf.MultiCell(contentW, 6, pdfText(subtitle), "", "C", false)
	}

	// ── metadata table
	metaY := r.pdf.GetY() + 10
	if metaY > 218 {
		metaY = 218
	}
	r.pdf.SetFont("Helvetica", "", 9.5)
	for i, kv := range meta {
		y := metaY + float64(i)*7.5
		r.pdf.SetTextColor(100, 116, 139)
		r.pdf.SetXY(marginX+26, y)
		r.pdf.CellFormat(52, 6, pdfText(strings.ToUpper(kv[0])), "", 0, "R", false, 0, "")
		r.pdf.SetTextColor(15, 23, 42)
		r.pdf.SetXY(marginX+82, y)
		r.pdf.CellFormat(66, 6, pdfText(kv[1]), "", 0, "L", false, 0, "")
	}

	// ── confidentiality note
	r.pdf.SetFont("Helvetica", "", 7.5)
	r.pdf.SetTextColor(148, 163, 184)
	r.pdf.SetXY(marginX, pageH-28)
	r.pdf.MultiCell(contentW, 4,
		"CONFIDENTIAL — Generated by WADJET from verified scanner observations recorded in the WADJET database at the time of export. "+
			"Findings reflect untrusted scanner output and must be reviewed by a qualified analyst before remediation decisions.",
		"", "C", false)
}

// ───────────────────────────────────────────── primitives

func (r *Renderer) fill(c color.RGBA, x, y, w, h float64) {
	r.pdf.SetFillColor(int(c.R), int(c.G), int(c.B))
	r.pdf.Rect(x, y, w, h, "F")
}

func (r *Renderer) drawCircle(x, y, rad float64, c color.RGBA) {
	r.pdf.SetFillColor(int(c.R), int(c.G), int(c.B))
	r.pdf.Circle(x, y, rad, "F")
}

// Section starts a numbered-style content section: bold uppercase emerald
// title with a rule beneath. Adds a page when little room remains.
func (r *Renderer) Section(heading string) {
	if r.pdf.GetY() > pageH-58 {
		r.AddContentPage()
	} else {
		r.pdf.Ln(4)
	}
	r.pdf.SetFont("Helvetica", "B", 11.5)
	r.pdf.SetTextColor(16, 185, 129)
	r.pdf.SetXY(marginX, r.pdf.GetY())
	r.pdf.CellFormat(contentW, 7, pdfText(strings.ToUpper(heading)), "", 1, "L", false, 0, "")
	y := r.pdf.GetY()
	r.pdf.SetDrawColor(203, 213, 225)
	r.pdf.SetLineWidth(0.35)
	r.pdf.Line(marginX, y, marginX+contentW, y)
	r.pdf.SetXY(marginX, y+2.5)
}

// SubSection draws a smaller bold heading.
func (r *Renderer) SubSection(heading string) {
	if r.pdf.GetY() > pageH-40 {
		r.AddContentPage()
	}
	r.pdf.Ln(2)
	r.pdf.SetFont("Helvetica", "B", 10)
	r.pdf.SetTextColor(15, 23, 42)
	r.pdf.SetXY(marginX, r.pdf.GetY())
	r.pdf.MultiCell(contentW, 5.6, pdfText(heading), "", "L", false)
	r.pdf.Ln(1)
}

// Para renders a justified body paragraph.
func (r *Renderer) Para(text string) {
	r.pdf.SetFont("Helvetica", "", 9.5)
	r.pdf.SetTextColor(51, 65, 85)
	r.pdf.SetXY(marginX, r.pdf.GetY())
	r.pdf.MultiCell(contentW, 4.8, pdfText(text), "", "L", false)
	r.pdf.Ln(1.5)
}

// Field draws a small uppercase field label line (DESCRIPTION, EVIDENCE…).
func (r *Renderer) Field(text string) {
	r.pdf.SetFont("Helvetica", "B", 9)
	r.pdf.SetTextColor(100, 116, 139)
	r.pdf.SetXY(marginX, r.pdf.GetY())
	r.pdf.CellFormat(contentW, 5, pdfText(text), "", 1, "L", false, 0, "")
}

// KeyValues draws a two-column definition list.
func (r *Renderer) KeyValues(pairs [][2]string) {
	for _, kv := range pairs {
		if r.pdf.GetY() > pageH-24 {
			r.AddContentPage()
		}
		r.pdf.SetFont("Helvetica", "B", 9)
		r.pdf.SetTextColor(100, 116, 139)
		r.pdf.SetXY(marginX, r.pdf.GetY())
		r.pdf.CellFormat(42, 5.4, pdfText(kv[0]), "", 0, "L", false, 0, "")
		r.pdf.SetFont("Helvetica", "", 9)
		r.pdf.SetTextColor(30, 41, 59)
		r.pdf.CellFormat(contentW-42, 5.4, pdfText(kv[1]), "", 1, "L", false, 0, "")
	}
	r.pdf.Ln(1)
}

// Chip draws one rounded severity/label chip and returns its width.
// Text is white on the color background.
func (r *Renderer) Chip(label string, c color.RGBA) float64 {
	r.pdf.SetFont("Helvetica", "B", 7.5)
	w := r.pdf.GetStringWidth(pdfText(label)) + 6
	x, y := r.pdf.GetXY()
	if x+w > marginX+contentW {
		r.pdf.SetXY(marginX, y+4.6)
		x, y = marginX, y+4.6
	}
	r.pdf.SetFillColor(int(c.R), int(c.G), int(c.B))
	r.pdf.SetDrawColor(int(c.R), int(c.G), int(c.B))
	r.pdf.RoundedRect(x, y, w, 4.4, 1.6, "1234", "F")
	r.pdf.SetTextColor(255, 255, 255)
	r.pdf.SetXY(x, y)
	r.pdf.CellFormat(w, 4.4, pdfText(label), "", 0, "C", false, 0, "")
	r.pdf.SetXY(x+w+2, y)
	return w
}

// SeverityChip draws the chip for a severity value (falls back to info).
func (r *Renderer) SeverityChip(sev string) {
	c, ok := severityColors[strings.ToLower(sev)]
	if !ok {
		c = severityColors["info"]
	}
	r.Chip(strings.ToUpper(sev), c)
}

// ChipRow renders a row of chips at the current position and ends the line.
func (r *Renderer) ChipRow(items []string, c color.RGBA) {
	if len(items) == 0 {
		return
	}
	r.pdf.SetXY(marginX, r.pdf.GetY()+1)
	for _, it := range items {
		r.Chip(it, c)
	}
	r.pdf.SetXY(marginX, r.pdf.GetY()+6)
}

// wrapLong hard-splits any byte sequence wider than w so that a single
// untrusted token (e.g. a 10k-char hash with no spaces) can never break
// the layout. Operates on the WinAnsi byte strings produced by pdfText.
func (r *Renderer) wrapLong(in []byte, w float64) []string {
	if r.pdf.GetStringWidth(string(in)) <= w {
		return []string{string(in)}
	}
	var out []string
	var cur strings.Builder
	var curW float64
	for _, b := range in {
		rw := r.pdf.GetStringWidth(string([]byte{b}))
		if curW+rw > w {
			out = append(out, cur.String())
			cur.Reset()
			curW = 0
		}
		cur.WriteByte(b)
		curW += rw
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// cellLines splits text on newlines (via gofpdf, honoring the column width)
// and then hard-wraps any over-wide token.
func (r *Renderer) cellLines(text string, w float64) []string {
	var out []string
	for _, ln := range r.pdf.SplitLines([]byte(text), w) {
		out = append(out, r.wrapLong(ln, w)...)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// MonoBlock renders verbatim evidence: monospace, panel fill, emerald
// accent bar. text must already be sanitized and length-capped.
func (r *Renderer) MonoBlock(text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	r.pdf.SetFont("Courier", "", 8)
	lines := r.cellLines(pdfText(text), contentW-8)
	h := float64(len(lines))*3.9 + 4
	if h > pageH-footerY-8 {
		h = pageH - footerY - 8 // pathological single-line input; gofpdf clips
	}
	if r.pdf.GetY()+h > pageH-24 {
		r.AddContentPage()
	}
	y := r.pdf.GetY()
	r.fill(clrPanel, marginX, y, contentW, h)
	r.fill(clrEmerald, marginX, y, 1.4, h)
	r.pdf.SetTextColor(30, 41, 59)
	for i, ln := range lines {
		r.pdf.SetXY(marginX+4, y+2+float64(i)*3.9)
		r.pdf.CellFormat(contentW-8, 3.9, string(ln), "", 0, "L", false, 0, "")
	}
	r.pdf.SetXY(marginX, y+h+2)
}

// Table renders a zebra-striped table with an emerald header band. widths
// are column widths in mm (should sum to about contentW). Cells wrap.
func (r *Renderer) Table(headers []string, widths []float64, rows [][]string) {
	lineH, pad := 4.0, 1.4
	r.pdf.SetFont("Helvetica", "B", 8)
	// header band
	if r.pdf.GetY()+lineH*2 > pageH-24 {
		r.AddContentPage()
	}
	y := r.pdf.GetY()
	r.fill(clrEmerald, marginX, y, contentW, lineH+2*pad)
	r.pdf.SetTextColor(255, 255, 255)
	x := marginX
	for i, htxt := range headers {
		r.pdf.SetXY(x+1.5, y+pad)
		r.pdf.MultiCell(widths[i]-3, lineH, pdfText(htxt), "", "L", false)
		x += widths[i]
	}
	y += lineH + 2*pad
	r.pdf.SetXY(marginX, y)

	// body rows
	r.pdf.SetFont("Helvetica", "", 8)
	for ri, row := range rows {
		// split every cell first, row height = tallest cell
		cells := make([][][]byte, len(row))
		maxLines := 1
		for i := range row {
			// keep explicit newlines, then wrap to the column width
			cells[i] = r.pdf.SplitLines([]byte(pdfText(row[i])), widths[i]-3)
			if n := len(cells[i]); n > maxLines {
				maxLines = n
			}
		}
		rowH := float64(maxLines)*lineH + 2*pad
		if r.pdf.GetY()+rowH > pageH-24 {
			r.AddContentPage()
		}
		y = r.pdf.GetY()
		if ri%2 == 1 {
			r.fill(clrZebra, marginX, y, contentW, rowH)
		}
		r.pdf.SetDrawColor(226, 232, 240)
		r.pdf.SetLineWidth(0.2)
		r.pdf.Rect(marginX, y, contentW, rowH, "D")
		r.pdf.SetTextColor(30, 41, 59)
		x = marginX
		for i, lines := range cells {
			if i >= len(widths) {
				break
			}
			r.pdf.SetXY(x+1.5, y+pad)
			for _, ln := range lines {
				r.pdf.CellFormat(widths[i]-3, lineH, string(ln), "", 0, "L", false, 0, "")
				r.pdf.SetXY(x+1.5, r.pdf.GetY()+lineH)
			}
			x += widths[i]
		}
		r.pdf.SetXY(marginX, y+rowH)
	}
	r.pdf.Ln(2)
}

// BarChart draws a horizontal bar chart of severity counts using filled
// rectangles in the severity colors, with counts and percentages.
func (r *Renderer) BarChart(counts map[string]int, total int) {
	if total == 0 {
		r.Para("No findings were recorded for this scope.")
		return
	}
	max := 0
	for _, s := range severityOrder {
		if c := counts[s]; c > max {
			max = c
		}
	}
	const labelW, barMax = 30.0, 118.0
	for _, sev := range severityOrder {
		n := counts[sev]
		if r.pdf.GetY() > pageH-32 {
			r.AddContentPage()
		}
		y := r.pdf.GetY()
		c := severityColors[sev]
		// severity color square + label
		r.fill(c, marginX, y+0.8, 4, 4)
		r.pdf.SetFont("Helvetica", "B", 9)
		r.pdf.SetTextColor(15, 23, 42)
		r.pdf.SetXY(marginX+6.5, y)
		r.pdf.CellFormat(labelW, 5.6, strings.ToUpper(sev), "", 0, "L", false, 0, "")
		// track
		r.fill(clrPanel, marginX+labelW+8, y+1, barMax, 4)
		// bar
		if n > 0 {
			w := barMax * float64(n) / float64(max)
			if w < 1.4 {
				w = 1.4
			}
			r.fill(c, marginX+labelW+8, y+1, w, 4)
		}
		// count + share
		r.pdf.SetFont("Helvetica", "", 9)
		r.pdf.SetTextColor(71, 85, 105)
		r.pdf.SetXY(marginX+labelW+8+barMax+3, y)
		r.pdf.CellFormat(contentW-labelW-barMax-11, 5.6,
			fmt.Sprintf("%d (%.0f%%)", n, 100*float64(n)/float64(total)), "", 0, "L", false, 0, "")
		r.pdf.SetXY(marginX, y+7)
	}
	r.pdf.Ln(2)
}
