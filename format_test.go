package pdfsign

import (
	"bytes"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestFormat_Enforcement(t *testing.T) {
	// Setup PKI
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Test Signer")

	// Open dummy document
	doc, err := OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test PAdES_B_T requires TSA
	t.Run("PAdES_B_T_MissingTSA", func(t *testing.T) {
		doc.pendingSigns = nil // Clear previous
		doc.Sign(key, cert).Format(PAdES_B_T)

		_, err := doc.Write(&bytes.Buffer{})
		if err == nil {
			t.Error("Expected error for PAdES_B_T without TSA, got nil")
		} else if err.Error() != "PAdES_B_T format requires a Timestamp Authority (TSA) URL" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	// 2. Test Unsupported Formats
	t.Run("Unsupported_Formats", func(t *testing.T) {
		formats := []Format{PAdES_B_LTA, C2PA, JAdES_B_T}
		for _, f := range formats {
			doc.pendingSigns = nil
			doc.Sign(key, cert).Format(f)

			_, err := doc.Write(&bytes.Buffer{})
			if err == nil {
				t.Errorf("Expected error for unsupported format %v, got nil", f)
			}
		}
	})

	// 3. Test PAdES_B (should succeed and NOT require revocation)
	t.Run("PAdES_B_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B, got error: %v", err)
		}
	})

	// 4. Test PAdES_B_LT (default) - should succeed
	t.Run("PAdES_B_LT_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B_LT)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B_LT, got error: %v", err)
		}
	})
}
