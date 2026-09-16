package sign

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/internal/testdss"
	"github.com/digitorus/pdfsign/revocation"
)

func TestValidateDSSValidation(t *testing.T) {
	apiURL := os.Getenv("DSS_API_URL")
	if apiURL == "" {
		t.Skip("DSS_API_URL not set, skipping DSS validation")
	}

	sourceDir := "../testfiles"
	sourceFiles, err := os.ReadDir(sourceDir)
	if err != nil {
		t.Fatalf("failed to read testfiles directory: %v", err)
	}

	cert, pkey := LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.Fatal("failed to load certificate or key")
	}

	outputDir := t.TempDir()
	client := testdss.New(apiURL)

	for _, f := range sourceFiles {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}
		// The first signature already present in testfile_multi.pdf reports
		// TOTAL_FAILED/FORMAT_FAILURE in DSS before any new signature is added.
		if f.Name() == "testfile_multi.pdf" {
			continue
		}

		fileName := f.Name()
		t.Run(fileName, func(t *testing.T) {
			inputPath := filepath.Join(sourceDir, fileName)
			outputPath := filepath.Join(outputDir, strings.TrimSuffix(fileName, ".pdf")+"_generated.pdf")

			if err := SignFile(inputPath, outputPath, SignData{
				Signature: SignDataSignature{
					Info: SignDataSignatureInfo{
						Name:        "John Doe",
						Location:    "Somewhere",
						Reason:      "DSS Validation Test",
						ContactInfo: "None",
						Date:        time.Now().Local(),
					},
					CertType:   CertificationSignature,
					DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
				},
				TSA: TSA{
					URL: "http://timestamp.digicert.com",
				},
				RevocationData:     revocation.InfoArchival{},
				RevocationFunction: DefaultEmbedRevocationStatusFunction,
				Signer:             pkey,
				Certificate:        cert,
			}); err != nil {
				t.Fatalf("failed to sign %s: %v", fileName, err)
			}

			content, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("failed to read signed file: %v", err)
			}

			dssResp, err := client.Validate(context.Background(), filepath.Base(outputPath), content)
			if err != nil {
				t.Fatalf("DSS validation failed: %v", err)
			}

			allPassed := true
			for i, sig := range dssResp.Signatures() {
				t.Logf("Signature #%d: Format=%s, Indication=%s, SubIndication=%s", i+1, sig.SignatureFormat, sig.Indication, sig.SubIndication)
				// Allow INDETERMINATE due to missing trust anchors, but reject
				// TOTAL_FAILED because it indicates a structural or integrity failure.
				if sig.Indication == "TOTAL_FAILED" {
					allPassed = false
				}
			}

			if !allPassed {
				t.Error("one or more signatures have TOTAL_FAILED indication")
			}

			if dssResp.SimpleReport.ValidSignaturesCount == 0 {
				t.Log("WARNING: No signatures were fully validated (trust issues?), but none failed integrity checks.")
			}

			if len(dssResp.DetailedReport) == 0 {
				t.Error("received empty DetailedReport")
			} else {
				t.Log("DetailedReport received, analyzing failures...")
				walkDetailedReport(t, dssResp.DetailedReport, "")
			}

			if len(dssResp.DiagnosticData) == 0 {
				t.Error("received empty DiagnosticData")
			} else {
				t.Log("DiagnosticData received")
				if usedPolicy, ok := dssResp.DiagnosticData["UsedValidationPolicy"]; ok {
					t.Logf("Used Validation Policy: %v", usedPolicy)
				}
			}
		})
	}
}

func walkDetailedReport(t *testing.T, node interface{}, path string) {
	switch v := node.(type) {
	case map[string]interface{}:
		// Check for Status indicating failure/warning
		if status, ok := v["Status"]; ok {
			if s, ok := status.(string); ok && (s == "KO" || s == "WARNING") {
				// Try to find a human-readable name or ID for context
				name := "Unknown"
				if n, ok := v["Name"]; ok {
					name = fmt.Sprintf("%v", n)
				} else if id, ok := v["Id"]; ok {
					name = fmt.Sprintf("%v", id)
				} else if title, ok := v["Title"]; ok {
					name = fmt.Sprintf("%v", title)
				}

				// Look for extra info like Error/Warning message
				errorMsg := ""
				if e, ok := v["Error"]; ok {
					errorMsg = fmt.Sprintf(" Error: %v", e)
				}
				if w, ok := v["Warning"]; ok {
					errorMsg = fmt.Sprintf(" Warning: %v", w)
				}
				t.Logf("[Constraint %s] Path: %s | Id: %v | Name: %s | Status: %s%s", s, path, v["Id"], name, s, errorMsg)
			}
		}

		for k, val := range v {
			var newPath string
			if path == "" {
				newPath = k
			} else {
				newPath = path + "." + k
			}
			walkDetailedReport(t, val, newPath)
		}
	case []interface{}:
		for i, val := range v {
			walkDetailedReport(t, val, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}
