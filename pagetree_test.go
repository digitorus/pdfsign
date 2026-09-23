package pdfsign

import (
	"bytes"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpdf"
)

// buildPageTreePDF opens a document built from the given objects, numbered
// from 1, with object 1 as the catalog.
func buildPageTreePDF(t *testing.T, objects ...string) *Document {
	t.Helper()
	b := testpdf.Bytes(objects...)
	doc, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return doc
}

// TestFindPageCycle checks that the page tree walk behind initials placement
// terminates on a crafted /Kids cycle and still finds the pages it holds.
func TestFindPageCycle(t *testing.T) {
	doc := buildPageTreePDF(t,
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 2 0 R 4 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	)

	for pageNum, width := range map[int]int64{1: 100, 2: 200} {
		page, err := doc.findPage(pageNum)
		if err != nil {
			t.Fatalf("findPage(%d): %v", pageNum, err)
		}
		if got := page.Key("MediaBox").Index(2).Int64(); got != width {
			t.Errorf("findPage(%d) has width %d, want %d", pageNum, got, width)
		}
	}

	if page, err := doc.findPage(3); err == nil || !page.IsNull() {
		t.Errorf("findPage(3) = %v, %v; want an error and no page", page, err)
	}
}
