package forms_test

import (
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/forms"
	"github.com/digitorus/pdfsign/internal/testpdf"
)

// buildFormPDF builds a one-page PDF with an AcroForm whose /Fields array is
// [4 0 R], followed by the given objects numbered from 4.
func buildFormPDF(t *testing.T, objects ...string) *pdf.Reader {
	t.Helper()
	return testpdf.Reader(t, append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}, objects...)...)
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
		if _, ok := m["form"]; !ok {
			t.Errorf("MapFields = %v, want the typed parent form mapped as well", m)
		}
	})

	t.Run("a parent's /V is the default of its kids", func(t *testing.T) {
		rdr := buildFormPDF(t,
			"<< /T (form) /FT /Tx /V (default) /Kids [5 0 R 6 0 R] >>",
			"<< /Parent 4 0 R /T (a) /V (Ada) >>",
			"<< /Parent 4 0 R /T (b) >>",
		)

		fields := forms.Extract(rdr)
		if len(fields) != 2 || fields[0].Name != "form.a" || fields[0].Value != "Ada" || fields[1].Name != "form.b" || fields[1].Value != "default" {
			t.Errorf("Extract = %+v, want form.a = Ada and form.b = default", fields)
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
