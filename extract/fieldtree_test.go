package extract_test

import (
	"bytes"
	"fmt"
	"testing"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/extract"
)

// buildFormPDF builds a one-page PDF with an AcroForm whose /Fields array is
// [4 0 R], followed by the given objects numbered from 4.
func buildFormPDF(t *testing.T, objects ...string) []byte {
	t.Helper()

	all := append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}, objects...)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(all))
	for i, obj := range all {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(all)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(all)+1, xref)
	return buf.Bytes()
}

// TestIterFieldTree covers the AcroForm field tree walk behind Iter: /FT is
// inherited from a parent field (ISO 32000-1 Table 220) and a /Kids cycle in a
// crafted document terminates.
func TestIterFieldTree(t *testing.T) {
	count := func(t *testing.T, fileBytes []byte) int {
		t.Helper()
		file := bytes.NewReader(fileBytes)
		rdr, err := pdflib.NewReader(file, int64(len(fileBytes)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		n := 0
		for _, err := range extract.Iter(rdr, file) {
			if err != nil {
				t.Fatalf("Iter: %v", err)
			}
			n++
		}
		return n
	}

	t.Run("/FT inherited from the parent field is honoured", func(t *testing.T) {
		got := count(t, buildFormPDF(t,
			"<< /T (form) /FT /Sig /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (sig1) /V 6 0 R >>",
			"<< /Type /Sig /Filter /Adobe.PPKLite /Contents <01> /ByteRange [0 0 0 0] >>",
		))
		if got != 1 {
			t.Fatalf("Iter yielded %d signatures, want 1", got)
		}
	})

	t.Run("a /Kids cycle terminates", func(t *testing.T) {
		got := count(t, buildFormPDF(t,
			"<< /T (a) /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (b) /Kids [4 0 R] >>",
		))
		if got != 0 {
			t.Fatalf("Iter yielded %d signatures, want 0", got)
		}
	})
}
