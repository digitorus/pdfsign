package sign

import (
	"archive/zip"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/revocation"
)

var (
	corpusPath     = flag.String("corpus", "", "path to local PDF corpus directory")
	downloadCorpus = flag.Bool("download-corpus", false, "download PDF corpora for testing")
	skipVeraPDF    = flag.Bool("skip-verapdf", false, "skip veraPDF validation")
	skipPdfcpu     = flag.Bool("skip-pdfcpu", false, "skip pdfcpu validation")
	skipGs         = flag.Bool("skip-gs", false, "skip ghostscript validation")
)

// CorpusSource defines a downloadable PDF corpus
type CorpusSource struct {
	Name    string
	URL     string
	SubPath string
}

var corpora = []CorpusSource{
	{
		Name:    "veraPDF-corpus",
		URL:     "https://github.com/veraPDF/veraPDF-corpus/archive/refs/heads/master.zip",
		SubPath: "veraPDF-corpus-master",
	},
	{
		Name:    "bfo-pdfa-testsuite",
		URL:     "https://github.com/bfosupport/pdfa-testsuite/archive/refs/heads/master.zip",
		SubPath: "pdfa-testsuite-master",
	},
}

// TestSignCorpus tests signing PDF files from various corpora
// and validates output with pdfcpu.
// Run with: go test -v -run TestSignCorpus -download-corpus -timeout 30m
func TestSignCorpus(t *testing.T) {
	// Skip first if no corpus path or download flag is specified
	if !*downloadCorpus && *corpusPath == "" {
		t.Skip("skipping corpus test: use -corpus flag or -download-corpus")
	}

	// Check if pdfcpu is available unless skipped
	if !*skipPdfcpu {
		if _, err := exec.LookPath("pdfcpu"); err != nil {
			t.Errorf("pdfcpu not found in PATH. pdfcpu is required for corpus testing to ensure structural integrity.")
			t.Logf("If you want to run the tests without pdfcpu, use the -skip-pdfcpu flag.")
			t.Logf("To install pdfcpu: go install github.com/pdfcpu/pdfcpu/cmd/pdfcpu@latest")
			t.FailNow()
		}
	}

	// Check if verapdf is available unless skipped
	if !*skipVeraPDF {
		if _, err := exec.LookPath("verapdf"); err != nil {
			t.Errorf("verapdf not found in PATH. veraPDF is required for corpus testing to ensure PDF/A compliance.")
			t.Logf("If you want to run the tests without veraPDF, use the -skip-verapdf flag.")
			t.Logf("To install veraPDF on macOS: brew install verapdf")
			t.FailNow()
		}
	}

	// Check if ghostscript is available unless skipped
	if !*skipGs {
		if _, err := exec.LookPath("gs"); err != nil {
			t.Errorf("ghostscript not found in PATH. ghostscript is used as a secondary PDF validator.")
			t.Logf("If you want to run the tests without ghostscript, use the -skip-gs flag.")
			t.Logf("To install ghostscript on macOS: brew install ghostscript")
			t.FailNow()
		}
	}

	cert, pkey := LoadCertificateAndKey(t)

	if *corpusPath != "" {
		// Test local corpus
		testLocalCorpus(t, *corpusPath, cert, pkey)
		return
	}

	// Download and test remote corpora
	cacheDir := os.Getenv("PDF_CORPUS_CACHE")
	if cacheDir == "" {
		var err error
		cacheDir, err = os.MkdirTemp("", "pdfsign-corpus-*")
		if err != nil {
			t.Fatalf("failed to create cache dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(cacheDir) }()
	}

	for _, corpus := range corpora {
		t.Run(corpus.Name, func(t *testing.T) {
			zipPath := filepath.Join(cacheDir, corpus.Name+".zip")

			if _, err := os.Stat(zipPath); os.IsNotExist(err) {
				if err := downloadFile(corpus.URL, zipPath); err != nil {
					t.Fatalf("failed to download corpus: %v", err)
				}
			}

			testZipCorpus(t, zipPath, corpus.SubPath, cert, pkey)
		})
	}
}

func testLocalCorpus(t *testing.T, path string, cert interface{}, key crypto.Signer) {
	var files []string
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.ToLower(filepath.Ext(p)) == ".pdf" {
			files = append(files, p)
		}
		return nil
	})

	t.Logf("Found %d PDF files in %s", len(files), path)

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			testSignPDFFile(t, f, cert, key)
		})
	}
}

func testZipCorpus(t *testing.T, zipPath, subPath string, cert interface{}, key crypto.Signer) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer func() { _ = r.Close() }()

	var pdfCount, signedCount, skippedCount int
	for _, f := range r.File {
		if subPath != "" && !strings.HasPrefix(f.Name, subPath) {
			continue
		}
		if f.FileInfo().IsDir() || strings.ToLower(filepath.Ext(f.Name)) != ".pdf" {
			continue
		}

		pdfCount++
		relName := strings.TrimPrefix(f.Name, subPath+"/")

		t.Run(relName, func(t *testing.T) {
			signed, skipped := testZipPDFFile(t, f, cert, key)
			if signed {
				signedCount++
			}
			if skipped {
				skippedCount++
			}
		})
	}

	t.Logf("Corpus %s: %d PDFs, signed %d, skipped %d (invalid source)",
		filepath.Base(zipPath), pdfCount, signedCount, skippedCount)
}

func testZipPDFFile(t *testing.T, zf *zip.File, cert interface{}, key crypto.Signer) (signed, skipped bool) {
	t.Helper()

	// Skip files that are intentionally non-compliant test cases
	baseName := filepath.Base(zf.Name)
	if strings.Contains(baseName, "-fail-") || strings.Contains(baseName, "_fail_") {
		t.Logf("skipping %s: intentionally non-compliant test file", baseName)
		return false, true
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SECURITY: panic on file %s: %v", zf.Name, r)
		}
	}()

	// Extract zip entry to temp file (avoids loading entire file into memory)
	tmpIn, err := os.CreateTemp("", "corpus-src-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpIn.Name()) }()

	rc, err := zf.Open()
	if err != nil {
		_ = tmpIn.Close()
		t.Fatalf("failed to open zip entry: %v", err)
	}

	_, err = io.Copy(tmpIn, rc)
	_ = rc.Close()
	_ = tmpIn.Close()
	if err != nil {
		t.Fatalf("failed to extract zip entry: %v", err)
	}

	// Validate source with all available validators
	sourceOK, sourceVera := validatePDFFile(t, tmpIn.Name(), "source")
	if !sourceOK {
		t.Logf("skipping %s: source file fails validation", zf.Name)
		return false, true
	}

	// Try to sign the file
	tmpOut, err := os.CreateTemp("", "corpus-signed-*.pdf")
	if err != nil {
		t.Fatalf("failed to create output temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpOut.Name()) }()
	_ = tmpOut.Close()

	if err := signPDFFile(t, tmpIn.Name(), tmpOut.Name(), cert, key); err != nil {
		t.Logf("signing failed (expected for some files): %v", err)
		return false, false
	}

	// Validate signed output with all available validators
	signedOK, signedVera := validatePDFFile(t, tmpOut.Name(), "signed")
	if !signedOK {
		t.Errorf("validation failed on signed output for %s", zf.Name)
		return false, false
	}

	// Compare veraPDF results
	if sourceVera != nil && signedVera != nil {
		if sourceVera.Compliant && !signedVera.Compliant {
			t.Errorf("veraPDF: %s was compliant but is now non-compliant after signing", zf.Name)
		} else if !sourceVera.Compliant && !signedVera.Compliant {
			if signedVera.FailedChecks > sourceVera.FailedChecks {
				t.Errorf("veraPDF: %s introduces %d new failed checks (%d -> %d)",
					zf.Name, signedVera.FailedChecks-sourceVera.FailedChecks,
					sourceVera.FailedChecks, signedVera.FailedChecks)
			}
		}
	}

	return true, false
}

func testSignPDFFile(t *testing.T, path string, cert interface{}, key crypto.Signer) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SECURITY: panic on file %s: %v", path, r)
		}
	}()

	// First validate source
	sourceOK, sourceVera := validatePDFFile(t, path, "source")
	if !sourceOK {
		t.Logf("skipping %s: source file fails validation", path)
		return
	}

	// Create temp file for output
	tmpOut, err := os.CreateTemp("", "corpus-signed-*.pdf")
	if err != nil {
		t.Fatalf("failed to create output temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpOut.Name()) }()
	_ = tmpOut.Close()

	// Try to sign the file
	if err := signPDFFile(t, path, tmpOut.Name(), cert, key); err != nil {
		t.Logf("signing failed: %v", err)
		return
	}

	// Validate signed output
	signedOK, signedVera := validatePDFFile(t, tmpOut.Name(), "signed")
	if !signedOK {
		t.Errorf("validation failed on signed output for %s", path)
	}

	// Compare veraPDF results
	if sourceVera != nil && signedVera != nil {
		if sourceVera.Compliant && !signedVera.Compliant {
			t.Errorf("veraPDF: %s was compliant but is now non-compliant after signing", path)
		} else if !sourceVera.Compliant && !signedVera.Compliant {
			if signedVera.FailedChecks > sourceVera.FailedChecks {
				t.Errorf("veraPDF: %s introduces %d new failed checks (%d -> %d)",
					path, signedVera.FailedChecks-sourceVera.FailedChecks,
					sourceVera.FailedChecks, signedVera.FailedChecks)
			}
		}
	}
}

// VeraPDFResult contains the summary of a veraPDF validation run.
type VeraPDFResult struct {
	Compliant    bool
	FailedChecks int
}

// validatePDFFile validates a PDF file using all available validators.
// Returns success if mandatory validators pass, and the veraPDF result if available.
func validatePDFFile(t *testing.T, path, label string) (bool, *VeraPDFResult) {
	t.Helper()

	success := true

	// pdfcpu is required unless skipped
	if !*skipPdfcpu {
		if !validateFileWithPdfcpu(t, path) {
			t.Logf("pdfcpu %s validation failed for %s", label, path)
			success = false
		}
	}

	// Ghostscript is used if available and not skipped
	if !*skipGs {
		if _, err := exec.LookPath("gs"); err == nil {
			if !validateFileWithGhostscript(t, path) {
				t.Logf("ghostscript %s validation failed for %s", label, path)
				success = false
			}
		}
	}

	var veraResult *VeraPDFResult
	// veraPDF is optional and used if available and not skipped
	if !*skipVeraPDF {
		if _, err := exec.LookPath("verapdf"); err == nil {
			veraResult = validateFileWithVeraPDF(t, path)
			if veraResult != nil && !veraResult.Compliant {
				t.Logf("verapdf %s non-compliant (%d failed checks) for %s", label, veraResult.FailedChecks, path)
			}
		}
	}

	return success, veraResult
}

// signPDFFile signs a PDF file and writes the result to outputPath.
func signPDFFile(t *testing.T, inputPath, outputPath string, cert interface{}, key crypto.Signer) error {
	t.Helper()

	signData := SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "Corpus Test",
				Location:    "Test",
				Reason:      "Corpus Testing",
				ContactInfo: "test@example.com",
				Date:        time.Now(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            key,
		Certificate:       cert.(*x509.Certificate),
		CertificateChains: [][]*x509.Certificate{{cert.(*x509.Certificate)}},
		RevocationFunction: func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
			return nil
		},
	}

	return SignFile(inputPath, outputPath, signData)
}

// validateFileWithPdfcpu validates a PDF file using pdfcpu.
func validateFileWithPdfcpu(t *testing.T, path string) bool {
	t.Helper()

	cmd := exec.Command("pdfcpu", "validate", "-mode", "relaxed", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("pdfcpu validation output: %s", string(output))
		return false
	}
	return true
}

// validateFileWithGhostscript validates a PDF file using ghostscript.
func validateFileWithGhostscript(t *testing.T, path string) bool {
	t.Helper()

	cmd := exec.Command("gs", "-dBATCH", "-dNOPAUSE", "-dQUIET", "-sDEVICE=nullpage", path)
	return cmd.Run() == nil
}

// validateFileWithVeraPDF validates a PDF file using veraPDF and returns the result.
func validateFileWithVeraPDF(t *testing.T, path string) *VeraPDFResult {
	t.Helper()

	cmd := exec.Command("verapdf", "--format", "json", path)
	output, err := cmd.Output() // Ignore exit code, verapdf returns non-zero for non-compliant files
	if err != nil && len(output) == 0 {
		t.Logf("verapdf execution failed: %v", err)
		return nil
	}

	var report struct {
		BatchResults []struct {
			ValidationResult struct {
				Compliant bool `json:"compliant"`
				Details   []struct {
					FailedChecks int `json:"failedChecks"`
				} `json:"details"`
			} `json:"validationResult"`
		} `json:"batchResults"`
	}

	if err := json.Unmarshal(output, &report); err != nil {
		t.Logf("failed to parse verapdf output: %v", err)
		return nil
	}

	if len(report.BatchResults) == 0 {
		return nil
	}

	res := &VeraPDFResult{
		Compliant: report.BatchResults[0].ValidationResult.Compliant,
	}

	for _, d := range report.BatchResults[0].ValidationResult.Details {
		res.FailedChecks += d.FailedChecks
	}

	return res
}

func downloadFile(url, destPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, resp.Body)
	return err
}
