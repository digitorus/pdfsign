package forms_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/forms"
)

// buildFormPDF builds a one-page PDF whose AcroForm /Fields array is
// [4 0 R], followed by the given objects numbered from 4.
func buildFormPDF(t *testing.T, objects ...string) *pdf.Reader {
	t.Helper()

	all := append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>",
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

	rdr, err := pdf.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return rdr
}

// TestExtractFieldTree covers the AcroForm field tree walk behind Extract and
// MapFields: /FT is inherited from a parent field (ISO 32000-1 Table 220), a
// nested field gets its fully qualified name, and a /Kids cycle terminates.
func TestExtractFieldTree(t *testing.T) {
	t.Run("nested fields inherit /FT and are named in full", func(t *testing.T) {
		rdr := buildFormPDF(t,
			"<< /T (form) /FT /Tx /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (name) /V (Ada) >>",
		)

		fields := forms.Extract(rdr)
		if len(fields) != 1 || fields[0].Name != "form.name" || fields[0].Type != "Tx" || fields[0].Value != "Ada" {
			t.Errorf("Extract = %+v, want one Tx field form.name = Ada", fields)
		}

		m := make(map[string]pdf.Value)
		forms.MapFields(rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0), "", m)
		if v, ok := m["form.name"]; !ok || v.Key("V").RawString() != "Ada" {
			t.Errorf("MapFields = %v, want form.name mapped to the terminal field", m)
		}
	})

	t.Run("a /Kids cycle terminates", func(t *testing.T) {
		rdr := buildFormPDF(t,
			"<< /T (a) /FT /Tx /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (b) /Kids [4 0 R 6 0 R] >>",
			"<< /Parent 5 0 R /T (c) /V (x) >>",
		)
		fields := forms.Extract(rdr)
		if len(fields) != 1 || fields[0].Name != "a.b.c" {
			t.Errorf("Extract = %+v, want the single field a.b.c", fields)
		}
	})
}
