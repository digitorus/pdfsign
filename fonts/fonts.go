// Package fonts provides font resources and metrics for PDF documents.
//
// This package contains types and utilities for working with fonts in PDF signatures,
// including standard PDF fonts and TrueType font metrics parsing.
package fonts

import (
	"golang.org/x/image/font"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
)

// StandardType represents standard PDF fonts that are available in all PDF readers
// without embedding.
type StandardType int

const (
	// Helvetica is the standard sans-serif font.
	Helvetica StandardType = iota
	// HelveticaBold is bold Helvetica.
	HelveticaBold
	// HelveticaOblique is italic/oblique Helvetica.
	HelveticaOblique
	// TimesRoman is the standard serif font.
	TimesRoman
	// TimesBold is bold Times Roman.
	TimesBold
	// Courier is the standard monospace font.
	Courier
	// CourierBold is bold Courier.
	CourierBold
)

// Font represents a font resource that can be used in PDF appearances.
type Font struct {
	Name     string   // PostScript name of the font
	Data     []byte   // TrueType font data (nil for standard fonts)
	Hash     string   // SHA256 hash of font data for deduplication
	Embedded bool     // Whether the font should be embedded in the PDF
	Metrics  *Metrics // Parsed metrics for accurate text measurement
}

// Standard returns a Font for a standard PDF font (no embedding required).
// These fonts are guaranteed to be available in all PDF readers.
func Standard(ft StandardType) *Font {
	names := map[StandardType]string{
		Helvetica:        "Helvetica",
		HelveticaBold:    "Helvetica-Bold",
		HelveticaOblique: "Helvetica-Oblique",
		TimesRoman:       "Times-Roman",
		TimesBold:        "Times-Bold",
		Courier:          "Courier",
		CourierBold:      "Courier-Bold",
	}
	return &Font{Name: names[ft], Embedded: false}
}

// Metrics contains parsed font metrics for accurate text measurement.
type Metrics struct {
	UnitsPerEm  int
	GlyphWidths map[rune]int // Advance widths in font units
	font        *sfnt.Font
}

// ParseTTFMetrics parses a TrueType font file and extracts glyph metrics.
// This enables accurate text width calculations for layout.
func ParseTTFMetrics(data []byte) (*Metrics, error) {
	f, err := sfnt.Parse(data)
	if err != nil {
		return nil, err
	}

	unitsPerEm := f.UnitsPerEm()

	// Pre-populate common ASCII characters
	glyphWidths := make(map[rune]int)
	var buf sfnt.Buffer

	// Use unitsPerEm as the ppem for consistent scaling
	ppem := fixed.Int26_6(unitsPerEm) << 6 // Convert to 26.6 fixed point

	// Iterate through common character range (ASCII + common extended)
	for r := rune(32); r <= rune(255); r++ {
		idx, err := f.GlyphIndex(&buf, r)
		if err != nil || idx == 0 {
			continue
		}

		advance, err := f.GlyphAdvance(&buf, idx, ppem, font.HintingNone)
		if err != nil {
			continue
		}

		// advance is in 26.6 fixed point, convert to int (round)
		glyphWidths[r] = int(advance >> 6)
	}

	return &Metrics{
		UnitsPerEm:  int(unitsPerEm),
		GlyphWidths: glyphWidths,
		font:        f,
	}, nil
}

// GetStringWidth calculates the width of a string in points at the given font size.
func (m *Metrics) GetStringWidth(text string, fontSize float64) float64 {
	if m == nil || m.UnitsPerEm == 0 {
		// Fallback to approximation
		return float64(len(text)) * fontSize * 0.5
	}

	var totalWidth int
	for _, r := range text {
		if width, ok := m.GlyphWidths[r]; ok {
			totalWidth += width
		} else {
			// Use average width for unknown characters
			totalWidth += m.UnitsPerEm / 2
		}
	}

	// Convert from font units to points
	// width_in_points = (width_in_units / unitsPerEm) * fontSize
	return (float64(totalWidth) / float64(m.UnitsPerEm)) * fontSize
}

// GetGlyphWidth returns the width of a single rune in font units.
func (m *Metrics) GetGlyphWidth(r rune) int {
	if m == nil {
		return 0
	}
	if width, ok := m.GlyphWidths[r]; ok {
		return width
	}
	return m.UnitsPerEm / 2 // Default
}

// GetWidthsArray returns an array of widths for a PDF font dictionary (FirstChar=32, LastChar=255).
// Widths are scaled to 1000 units per em as per PDF specification.
func (m *Metrics) GetWidthsArray() []int {
	widths := make([]int, 256-32)
	defaultWidth := 500 // Fallback

	if m != nil && m.UnitsPerEm > 0 {
		// Scale to 1000 units (PDF convention)
		scale := 1000.0 / float64(m.UnitsPerEm)
		defaultWidth = int(float64(m.UnitsPerEm/2) * scale)

		for i := 32; i < 256; i++ {
			r := rune(i)
			if w, ok := m.GlyphWidths[r]; ok {
				widths[i-32] = int(float64(w) * scale)
			} else {
				widths[i-32] = defaultWidth
			}
		}
	} else {
		for i := range widths {
			widths[i] = defaultWidth
		}
	}

	return widths
}
