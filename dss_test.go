package pdfsign

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

type dssValidationResponse struct {
	SimpleReport struct {
		SignaturesCount int `json:"signaturesCount"`
		Entries         []struct {
			Signature *struct {
				SignatureFormat string `json:"signatureFormat"`
				Indication      string `json:"indication"`
				SubIndication   string `json:"subIndication"`
			} `json:"signature"`
		} `json:"signatureOrTimestampOrEvidenceRecord"`
	} `json:"simpleReport"`
}

// validateWithDSS submits fileBytes to the DSS validation API and returns the
// simple report.
func validateWithDSS(t *testing.T, apiUrl, name string, fileBytes []byte) dssValidationResponse {
	t.Helper()

	reqBody := map[string]any{
		"signedDocument": map[string]string{
			"bytes": base64.StdEncoding.EncodeToString(fileBytes),
			"name":  name,
		},
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	resp, err := http.Post(apiUrl, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("failed to call DSS API: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("DSS API returned status %d: %s", resp.StatusCode, string(body))
	}

	var dssResp dssValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&dssResp); err != nil {
		t.Fatalf("failed to decode DSS response: %v", err)
	}
	if dssResp.SimpleReport.SignaturesCount == 0 {
		t.Fatal("no signatures found by DSS")
	}
	return dssResp
}

// TestValidateDSSPAdESLevels validates fluent-API output with DSS and asserts
// the reported signature level: PAdES baselines for the PAdES formats and, as
// a negative case, the non-PAdES legacy profile for DefaultFormat. The chain
// and live revocation endpoints make it a realistic B-T case: disabled
// revocation embedding must not change the reported level.
func TestValidateDSSPAdESLevels(t *testing.T) {
	apiUrl := os.Getenv("DSS_API_URL")
	if apiUrl == "" {
		t.Skip("DSS_API_URL not set, skipping DSS validation")
	}

	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("DSS PAdES Signer")
	chain := [][]*x509.Certificate{append([]*x509.Certificate{cert}, pki.IntermediateCerts...)}

	if err := os.MkdirAll("testfiles/success", 0o755); err != nil {
		t.Fatalf("%v", err)
	}

	cases := []struct {
		name       string
		wantFormat string
		configure  func(*SignBuilder)
	}{
		{
			name:       "PAdES_B",
			wantFormat: "PAdES-BASELINE-B",
			configure:  func(sb *SignBuilder) { sb.Format(PAdES_B) },
		},
		{
			name:       "PAdES_B_T",
			wantFormat: "PAdES-BASELINE-T",
			configure: func(sb *SignBuilder) {
				sb.Format(PAdES_B_T).Timestamp(testpki.StartMockTSA(t))
			},
		},
		{
			// Negative: the legacy profile shall not be reported as PAdES.
			name:       "DefaultFormat",
			wantFormat: "PKCS7-B",
			configure:  func(sb *SignBuilder) { sb.Format(DefaultFormat) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := OpenFile("testfiles/testfile20.pdf")
			if err != nil {
				t.Fatalf("%v", err)
			}
			sb := doc.Sign(key, cert).CertificateChains(chain)
			tc.configure(sb)

			var buf bytes.Buffer
			if _, err := doc.Write(&buf); err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			// Persist so the outputs are part of the uploaded CI artifacts.
			artifact := filepath.Join("testfiles/success", "dss_"+tc.name+".pdf")
			if err := os.WriteFile(artifact, buf.Bytes(), 0o644); err != nil {
				t.Fatalf("%v", err)
			}

			dssResp := validateWithDSS(t, apiUrl, filepath.Base(artifact), buf.Bytes())
			checked := 0
			for _, entry := range dssResp.SimpleReport.Entries {
				sig := entry.Signature
				if sig == nil {
					continue
				}
				checked++
				t.Logf("Format=%s, Indication=%s, SubIndication=%s", sig.SignatureFormat, sig.Indication, sig.SubIndication)
				if sig.SignatureFormat != tc.wantFormat {
					t.Errorf("DSS reports signature format %q, want %q", sig.SignatureFormat, tc.wantFormat)
				}
				if strings.HasPrefix(tc.wantFormat, "PKCS7") && strings.HasPrefix(sig.SignatureFormat, "PAdES") {
					t.Errorf("legacy profile is reported as PAdES: %q", sig.SignatureFormat)
				}
				// The test PKI is untrusted, so INDETERMINATE is expected;
				// TOTAL_FAILED means broken structure or integrity.
				if sig.Indication == "TOTAL_FAILED" {
					t.Errorf("DSS reports TOTAL_FAILED (%s)", sig.SubIndication)
				}
			}
			if checked == 0 {
				t.Fatal("DSS simple report contains no signature entries")
			}
		})
	}
}
