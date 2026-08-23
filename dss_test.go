package pdfsign

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testdss"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// TestValidateDSSPAdESLevels validates fluent-API output with DSS and asserts
// the reported signature level: PAdES baselines for the PAdES formats and, as
// a negative case, the non-PAdES legacy profile for DefaultFormat. The chain
// and live revocation endpoints make it a realistic B-T case: disabled
// revocation embedding must not change the reported level.
func TestValidateDSSPAdESLevels(t *testing.T) {
	apiURL := os.Getenv("DSS_API_URL")
	if apiURL == "" {
		t.Skip("DSS_API_URL not set, skipping DSS validation")
	}

	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("DSS PAdES Signer")
	chain := [][]*x509.Certificate{append([]*x509.Certificate{cert}, pki.IntermediateCerts...)}
	client := testdss.New(apiURL)

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

			dssResp, err := client.Validate(context.Background(), "dss_"+tc.name+".pdf", buf.Bytes())
			if err != nil {
				t.Fatalf("DSS validation failed: %v", err)
			}

			for _, sig := range dssResp.Signatures() {
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
		})
	}
}
