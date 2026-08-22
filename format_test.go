package pdfsign

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pkcs7"
)

// revocationArchivalPresent reports whether the signature CMS in fileBytes
// carries the Adobe revocation-info archival signed attribute.
func revocationArchivalPresent(t *testing.T, fileBytes []byte) bool {
	t.Helper()

	contentsMatch := regexp.MustCompile(`/Contents<([0-9a-fA-F]+)>`).FindSubmatch(fileBytes)
	if contentsMatch == nil {
		t.Fatal("no /Contents entry found in signed file")
	}
	cms, err := hex.DecodeString(string(contentsMatch[1]))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	p7, err := pkcs7.Parse(cms)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	oid := asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}
	for _, attribute := range p7.Signers[0].AuthenticatedAttributes {
		if attribute.Type.Equal(oid) {
			return true
		}
	}
	return false
}

func TestFormat_Enforcement(t *testing.T) {
	// Setup PKI
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Test Signer")
	chain := [][]*x509.Certificate{append([]*x509.Certificate{cert}, pki.IntermediateCerts...)}

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
		formats := []Format{PAdES_B_LT, PAdES_B_LTA, C2PA, JAdES_B_T}
		for _, f := range formats {
			doc.pendingSigns = nil
			doc.Sign(key, cert).Format(f)

			_, err := doc.Write(&bytes.Buffer{})
			if err == nil {
				t.Errorf("Expected error for unsupported format %v, got nil", f)
			}
		}
	})

	// 3. Test PAdES_B (should succeed and NOT embed revocation material)
	t.Run("PAdES_B_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B).CertificateChains(chain)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")) {
			t.Error("PAdES_B output does not use SubFilter ETSI.CAdES.detached")
		}
		if revocationArchivalPresent(t, buf.Bytes()) {
			t.Error("PAdES_B output embeds revocation material")
		}
	})

	// 4. Test PAdES_B_T with a TSA (no revocation material either; it belongs
	// in the DSS at B-LT)
	t.Run("PAdES_B_T_Success", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(PAdES_B_T).Timestamp(testpki.StartMockTSA(t)).CertificateChains(chain)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for PAdES_B_T, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")) {
			t.Error("PAdES_B_T output does not use SubFilter ETSI.CAdES.detached")
		}
		if revocationArchivalPresent(t, buf.Bytes()) {
			t.Error("PAdES_B_T output embeds revocation material")
		}
	})

	// 5. Test DefaultFormat (legacy profile, embeds revocation material)
	t.Run("DefaultFormat_Legacy", func(t *testing.T) {
		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(DefaultFormat).CertificateChains(chain)

		var buf bytes.Buffer
		_, err := doc.Write(&buf)
		if err != nil {
			t.Errorf("Expected success for DefaultFormat, got error: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("/SubFilter /adbe.pkcs7.detached")) {
			t.Error("DefaultFormat output does not use the legacy SubFilter adbe.pkcs7.detached")
		}
		if !revocationArchivalPresent(t, buf.Bytes()) {
			t.Error("DefaultFormat output does not embed revocation material")
		}
	})

	// 6. Revocation fetching is bounded by the caller's context
	t.Run("Revocation_CanceledContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		doc.pendingSigns = nil
		doc.Sign(key, cert).Format(DefaultFormat).CertificateChains(chain).Context(ctx)

		_, err := doc.Write(&bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("got error %v, want a canceled context error", err)
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
