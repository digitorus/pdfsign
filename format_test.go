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
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")) {
			t.Error("PAdES_B output does not use SubFilter ETSI.CAdES.detached")
		}
	})

	// 4. Test PAdES_B_T with a TSA
	t.Run("PAdES_B_T_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B_T).Timestamp(testpki.StartMockTSA(t))

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B_T, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")) {
			t.Error("PAdES_B_T output does not use SubFilter ETSI.CAdES.detached")
		}
	})

	// 5. Test PAdES_B_LT (legacy profile until DSS support is added)
	t.Run("PAdES_B_LT_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B_LT)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B_LT, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /adbe.pkcs7.detached")) {
			t.Error("PAdES_B_LT output does not use the legacy SubFilter adbe.pkcs7.detached")
		}
	})

	// 6. Test DefaultFormat (legacy profile)
	t.Run("DefaultFormat_Legacy", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(DefaultFormat)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for DefaultFormat, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /adbe.pkcs7.detached")) {
			t.Error("DefaultFormat output does not use the legacy SubFilter adbe.pkcs7.detached")
		}
	})

	// 7. Document timestamps always use ETSI.RFC3161
	t.Run("DocumentTimestamp_RFC3161", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Timestamp(testpki.StartMockTSA(t)).Format(PAdES_B_T)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for document timestamp, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.RFC3161")) {
			t.Error("document timestamp does not use SubFilter ETSI.RFC3161")
		}
		if bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")) {
			t.Error("document timestamp must not use SubFilter ETSI.CAdES.detached")
		}
	})
}
