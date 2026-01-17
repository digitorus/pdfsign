package pdf

import (
	"bytes"
	"fmt"
	"io"

	pdflib "github.com/digitorus/pdf"
)

// ExtractPageAsXObject extracts a page from a PDF and returns the content stream
// and resources needed to embed it as a Form XObject.
func ExtractPageAsXObject(data []byte, pageNum int) (contentStream []byte, bbox [4]float64, err error) {
	r, err := pdflib.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, [4]float64{}, fmt.Errorf("failed to parse PDF: %w", err)
	}

	if pageNum < 1 || pageNum > r.NumPage() {
		return nil, [4]float64{}, fmt.Errorf("page %d out of range (1-%d)", pageNum, r.NumPage())
	}

	page := r.Page(pageNum)
	if page.V.IsNull() {
		return nil, [4]float64{}, fmt.Errorf("page %d not found", pageNum)
	}

	// Get MediaBox (or CropBox if present)
	mediaBox := page.V.Key("MediaBox")
	if mediaBox.IsNull() {
		// Default to letter size
		bbox = [4]float64{0, 0, 612, 792}
	} else {
		for i := 0; i < 4 && i < mediaBox.Len(); i++ {
			bbox[i] = mediaBox.Index(i).Float64()
		}
	}

	// Get content stream
	contents := page.V.Key("Contents")
	if contents.IsNull() {
		return nil, bbox, nil // Empty page
	}

	// Read the content stream
	var buf bytes.Buffer
	if contents.Kind() == pdflib.Array {
		// Multiple content streams
		for i := 0; i < contents.Len(); i++ {
			stream := contents.Index(i)
			reader := stream.Reader()
			if reader != nil {
				if _, err := io.Copy(&buf, reader); err != nil {
					return nil, bbox, fmt.Errorf("failed to copy content stream: %w", err)
				}
				buf.WriteString("\n")
			}
		}
	} else {
		// Single content stream
		reader := contents.Reader()
		if reader != nil {
			if _, err := io.Copy(&buf, reader); err != nil {
				return nil, bbox, fmt.Errorf("failed to copy content stream: %w", err)
			}
		}
	}

	return buf.Bytes(), bbox, nil
}
