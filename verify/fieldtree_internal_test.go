package verify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpdf"
)

// buildFormPDF builds a one-page PDF with an AcroForm whose /Fields array is
// [4 0 R], followed by the given objects numbered from 4.
func buildFormPDF(t *testing.T, objects ...string) []byte {
	t.Helper()
	return testpdf.Bytes(append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}, objects...)...)
}

// TestSignatureFieldTraversal covers the AcroForm field tree walk: /FT is
// inherited from a parent field (ISO 32000-1 Table 220) and a /Kids cycle in
// a crafted document terminates.
func TestSignatureFieldTraversal(t *testing.T) {
	verify := func(t *testing.T, fileBytes []byte) error {
		t.Helper()
		_, err := VerifyWithOptions(bytes.NewReader(fileBytes), int64(len(fileBytes)), DefaultVerifyOptions())
		return err
	}

	t.Run("/FT inherited from the parent field is honoured", func(t *testing.T) {
		// The signature field is found (its bogus signature then fails to
		// parse), which a walk without inheritance reports as no field at all.
		err := verify(t, buildFormPDF(t,
			"<< /T (form) /FT /Sig /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (sig1) /V 6 0 R >>",
			"<< /Type /Sig /Filter /Adobe.PPKLite /Contents <01> /ByteRange [0 0 0 0] >>",
		))
		if err == nil || !strings.Contains(err.Error(), "failed to process") {
			t.Fatalf("expected the signature field to be found and its signature rejected, got %v", err)
		}
	})

	t.Run("a /Kids cycle terminates", func(t *testing.T) {
		err := verify(t, buildFormPDF(t,
			"<< /T (a) /Kids [5 0 R] >>",
			"<< /Parent 4 0 R /T (b) /Kids [4 0 R] >>",
		))
		if err == nil || !strings.Contains(err.Error(), "none found") {
			t.Fatalf("expected no signature field to be found, got %v", err)
		}
	})
}
