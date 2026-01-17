package sign

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/revocation"
)

type DSSFile struct {
	Bytes string `json:"bytes"`
	Name  string `json:"name"`
}

type DSSValidationRequest struct {
	SignedDocument    DSSFile   `json:"signedDocument"`
	OriginalDocuments []DSSFile `json:"originalDocuments"`
	Policy            *DSSFile  `json:"policy,omitempty"`
}

type DSSValidationResponse struct {
	SimpleReport struct {
		Valid                bool `json:"valid"`
		SignaturesCount      int  `json:"signaturesCount"`
		ValidSignaturesCount int  `json:"validSignaturesCount"`
		Signature            []struct {
			Indication    string `json:"indication"`
			SubIndication string `json:"subIndication"`
		} `json:"signature"`
	} `json:"simpleReport"`
	DetailedReport map[string]interface{} `json:"detailedReport"`
	DiagnosticData map[string]interface{} `json:"diagnosticData"`
}

type TestProfile struct {
	Name      string
	PolicyXML string
}

func TestValidateDSSValidation(t *testing.T) {
	apiUrl := os.Getenv("DSS_API_URL")
	if apiUrl == "" {
		t.Skip("DSS_API_URL not set, skipping DSS validation")
	}

	// generate signed files for testing
	sourceDir := "../testfiles"
	successDir := "../testfiles/success"
	if err := os.MkdirAll(successDir, 0755); err != nil {
		t.Fatalf("failed to create success directory: %v", err)
	}

	sourceFiles, err := os.ReadDir(sourceDir)
	if err != nil {
		t.Fatalf("failed to read testfiles directory: %v", err)
	}

	cert, pkey := LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.Fatal("failed to load certificate or key")
	}

	for _, f := range sourceFiles {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}

		inputPath := filepath.Join(sourceDir, f.Name())
		outputPath := filepath.Join(successDir, strings.TrimSuffix(f.Name(), ".pdf")+"_generated.pdf")

		err := SignFile(inputPath, outputPath, SignData{
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
		})
		if err != nil {
			t.Logf("failed to sign %s: %v", f.Name(), err)
			continue
		}
	}

	files, err := os.ReadDir(successDir)
	if err != nil {
		t.Fatalf("failed to read testfiles/success: %v", err)
	}

	var pdfFiles []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".pdf" {
			pdfFiles = append(pdfFiles, filepath.Join(successDir, f.Name()))
		}
	}

	if len(pdfFiles) == 0 {
		t.Skip("no PDF files found in testfiles/success")
	}

	profiles := []TestProfile{
		{Name: "Default", PolicyXML: ""},
	}

	for _, profile := range profiles {
		t.Run("Profile="+profile.Name, func(t *testing.T) {
			var policy *DSSFile
			if profile.PolicyXML != "" {
				policy = &DSSFile{
					Bytes: base64.StdEncoding.EncodeToString([]byte(profile.PolicyXML)),
					Name:  "policy.xml",
				}
			}

			for _, pdfPath := range pdfFiles {
				t.Run(filepath.Base(pdfPath), func(t *testing.T) {
					content, err := os.ReadFile(pdfPath)
					if err != nil {
						t.Fatalf("failed to read file: %v", err)
					}

					reqBody := DSSValidationRequest{
						SignedDocument: DSSFile{
							Bytes: base64.StdEncoding.EncodeToString(content),
							Name:  filepath.Base(pdfPath),
						},
						Policy: policy,
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

					var dssResp DSSValidationResponse
					if err := json.NewDecoder(resp.Body).Decode(&dssResp); err != nil {
						t.Fatalf("failed to decode DSS response: %v", err)
					}

					if dssResp.SimpleReport.SignaturesCount == 0 {
						t.Errorf("no signatures found in %s", pdfPath)
						return
					}

					allPassed := true
					for i, sig := range dssResp.SimpleReport.Signature {
						t.Logf("Signature #%d: Indication=%s, SubIndication=%s", i+1, sig.Indication, sig.SubIndication)
						// Allow INDETERMINATE due to missing trust anchors (NO_CERTIFICATE_CHAIN_FOUND), but reject TOTAL_FAILED
						if sig.Indication == "TOTAL_FAILED" {
							allPassed = false
						}
					}

					if !allPassed {
						t.Errorf("one or more signatures have TOTAL_FAILED indication")
					}

					if dssResp.SimpleReport.ValidSignaturesCount == 0 {
						t.Logf("WARNING: No signatures were fully validated (trust issues?), but none failed integrity checks.")
					}

					if len(dssResp.DetailedReport) == 0 {
						t.Error("freceived empty DetailedReport")
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
