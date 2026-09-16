package pdf

import (
	"fmt"

	pdflib "github.com/digitorus/pdf"
)

// FontInfo contains information about a font found in the PDF.
type FontInfo struct {
	Name string
	ID   uint32
}

// ScanFonts iterates through the PDF to find existing font resources.
func ScanFonts(r *pdflib.Reader) ([]FontInfo, error) {
	if r == nil {
		return nil, nil
	}

	var found []FontInfo
	visited := make(map[uint32]bool)

	// Helper to process a font dictionary
	processFont := func(val pdflib.Value) {
		ptr := val.GetPtr()
		id := uint32(ptr.GetID())

		if visited[id] {
			return
		}
		visited[id] = true

		baseFont, err := ResolveFontName(r, id)
		if err == nil && baseFont != "" {
			found = append(found, FontInfo{Name: baseFont, ID: id})
		}
	}

	// 1. Check AcroForm Default Resources (global)
	root := r.Trailer().Key("Root")
	acroForm := root.Key("AcroForm")
	if !acroForm.IsNull() {
		dr := acroForm.Key("DR")
		if !dr.IsNull() {
			fonts := dr.Key("Font")
			if !fonts.IsNull() {
				keys := fonts.Keys()
				for _, name := range keys {
					processFont(fonts.Key(name))
				}
			}
		}
	}

	// 2. Iterate Pages (local resources)
	numPages := r.NumPage()
	for i := 1; i <= numPages; i++ {
		page := r.Page(i)
		resources := page.V.Key("Resources")
		if !resources.IsNull() {
			fonts := resources.Key("Font")
			if !fonts.IsNull() {
				keys := fonts.Keys()
				for _, name := range keys {
					processFont(fonts.Key(name))
				}
			}
		}
	}

	return found, nil
}

// ResolveFontName gets the BaseFont name from a font object ID
func ResolveFontName(r *pdflib.Reader, objID uint32) (string, error) {
	if r == nil {
		return "", fmt.Errorf("no reader available")
	}

	val, err := r.GetObject(objID)
	if err != nil {
		return "", fmt.Errorf("failed to get object %d: %w", objID, err)
	}

	if val.Kind() != pdflib.Dict && val.Kind() != pdflib.Stream {
		return "", fmt.Errorf("object %d is not a dict or stream, got %v", objID, val.Kind())
	}

	baseFontVal := val.Key("BaseFont")
	if baseFontVal.Kind() == pdflib.Name {
		return baseFontVal.Name(), nil
	}

	return "", nil
}
