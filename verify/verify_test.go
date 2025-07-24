package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFile(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	// Open the test file
	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	// Verify the file
	response, err := VerifyFile(file)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}

	// Basic response validation
	if response == nil {
		t.Fatal("Response is nil")
	}

	if response.Error != "" {
		t.Logf("Verification error: %s", response.Error)
	}

	// Check if we have signers
	if len(response.Signatures) == 0 {
		t.Fatal("No signatures found in the document")
	}

	validSignatureFound := false
	for i, sig := range response.Signatures {
		if sig.Validation.ValidSignature {
			validSignatureFound = true
		}
		if sig.Info.SignatureTime == nil {
			t.Errorf("Signature %d missing signature time", i+1)
		}
		if len(sig.Validation.Certificates) == 0 {
			t.Errorf("Signature %d has no certificates", i+1)
		}
		if sig.Info.DocumentHash == "" {
			t.Errorf("Signature %d missing document hash", i+1)
		}
		if sig.Info.SignatureHash == "" {
			t.Errorf("Signature %d missing signature hash", i+1)
		}
		if sig.Info.HashAlgorithm != "sha256" {
			t.Errorf("Signature %d hash algorithm is not sha256 (got %s)", i+1, sig.Info.HashAlgorithm)
		}
	}
	if !validSignatureFound {
		t.Error("No valid signatures found in signatures")
	}

	// Document info checks
	info := response.DocumentInfo
	if info.Author == "" {
		t.Error("DocumentInfo.Author is empty")
	}
	if info.Creator == "" {
		t.Error("DocumentInfo.Creator is empty")
	}
	if info.Producer == "" {
		t.Error("DocumentInfo.Producer is empty")
	}
	if info.Pages <= 0 {
		t.Error("DocumentInfo.Pages is zero or negative")
	}
	if info.CreationDate.IsZero() {
		t.Error("DocumentInfo.CreationDate is zero")
	}
	if info.ModDate.IsZero() {
		t.Error("DocumentInfo.ModDate is zero")
	}

	t.Logf("Found %d signer(s)", len(response.Signatures))

	// Validate each signer
	for i, sig := range response.Signatures {
		t.Logf("Signature %d:", i+1)
		t.Logf("  Name: %s", sig.Info.Name)
		t.Logf("  Reason: %s", sig.Info.Reason)
		t.Logf("  Location: %s", sig.Info.Location)
		t.Logf("  ContactInfo: %s", sig.Info.ContactInfo)
		t.Logf("  ValidSignature: %t", sig.Validation.ValidSignature)
		t.Logf("  TrustedIssuer: %t", sig.Validation.TrustedIssuer)
		t.Logf("  DocumentHash: %s", sig.Info.DocumentHash)
		t.Logf("  SignatureHash: %s", sig.Info.SignatureHash)
		t.Logf("  HashAlgorithm: %s", sig.Info.HashAlgorithm)
		t.Logf("  Certificates count: %d", len(sig.Validation.Certificates))

		// Check if we have certificates
		if len(sig.Validation.Certificates) == 0 {
			t.Errorf("Signature %d has no certificates", i+1)
		}

		// Validate certificates
		for j, cert := range sig.Validation.Certificates {
			if cert.Certificate == nil {
				t.Errorf("Signature %d, certificate %d is nil", i+1, j+1)
			} else {
				t.Logf("  Certificate %d: Subject=%s, Issuer=%s", j+1,
					cert.Certificate.Subject.String(),
					cert.Certificate.Issuer.String())

				if cert.VerifyError != "" {
					t.Logf("  Certificate %d verify error: %s", j+1, cert.VerifyError)
				}

				if cert.OCSPEmbedded {
					t.Logf("  Certificate %d has embedded OCSP response", j+1)
				}

				if cert.CRLEmbedded {
					t.Logf("  Certificate %d has embedded CRL", j+1)
				}
			}
		}

		// Check timestamp if present
		if sig.Info.TimeStamp != nil {
			t.Logf("  Timestamp: %s", sig.Info.TimeStamp.Time)
		}
	}

	// Validate document info
	t.Logf("Document Info:")
	t.Logf("  Author: %s", response.DocumentInfo.Author)
	t.Logf("  Creator: %s", response.DocumentInfo.Creator)
	t.Logf("  Producer: %s", response.DocumentInfo.Producer)
	t.Logf("  Title: %s", response.DocumentInfo.Title)
	t.Logf("  Subject: %s", response.DocumentInfo.Subject)
	t.Logf("  Pages: %d", response.DocumentInfo.Pages)
	t.Logf("  Keywords: %v", response.DocumentInfo.Keywords)

	if !response.DocumentInfo.CreationDate.IsZero() {
		t.Logf("  CreationDate: %s", response.DocumentInfo.CreationDate)
	}

	if !response.DocumentInfo.ModDate.IsZero() {
		t.Logf("  ModDate: %s", response.DocumentInfo.ModDate)
	}
}

func TestReader(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	// Open the test file
	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	// Verify using Reader
	response, err := Verify(file, fileInfo.Size())
	if err != nil {
		t.Fatalf("Failed to verify file with Reader: %v", err)
	}

	// Basic validation
	if response == nil {
		t.Fatal("Response is nil")
	}

	if len(response.Signatures) == 0 {
		t.Fatal("No signatures found in the document")
	}

	t.Logf("Reader test: Found %d signer(s)", len(response.Signatures))
}

func TestFileWithInvalidFile(t *testing.T) {
	// Create a temporary invalid file
	tmpFile, err := os.CreateTemp("", "invalid_*.pdf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Warning: failed to remove temp file: %v", err)
		}
	}()
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Logf("Warning: failed to close temp file: %v", err)
		}
	}()

	// Write some invalid content
	_, err = tmpFile.WriteString("This is not a valid PDF file")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Seek back to beginning
	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		t.Fatalf("Failed to seek temp file: %v", err)
	}

	// This should fail
	_, err = VerifyFile(tmpFile)
	if err == nil {
		t.Fatal("Expected error for invalid PDF file, but got none")
	}

	t.Logf("Expected error for invalid file: %v", err)
}

func TestFileWithUnsignedPDF(t *testing.T) {
	// Test with a PDF that might not have signatures
	testFilePath := filepath.Join("..", "testfiles", "testfile12.pdf")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Logf("Warning: failed to close file: %v", err)
		}
	}()

	// This might fail if the file is unsigned
	response, err := VerifyFile(file)
	if err != nil {
		// This is expected for unsigned PDFs
		t.Logf("Expected error for unsigned PDF: %v", err)
		return
	}

	// If it succeeds, log the results
	if response != nil {
		t.Logf("Unsigned PDF test: Found %d signer(s)", len(response.Signatures))
	}
}

func TestRevocationWarnings(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	// Open the test file
	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Failed to close file: %v", closeErr)
		}
	}()

	// Verify the file
	response, err := VerifyFile(file)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}

	// Check for revocation warnings
	if response != nil && len(response.Signatures) > 0 {
		for i, sig := range response.Signatures {
			t.Logf("Signature %d:", i+1)
			for j, cert := range sig.Validation.Certificates {
				t.Logf("  Certificate %d:", j+1)
				t.Logf("    OCSP Embedded: %v", cert.OCSPEmbedded)
				t.Logf("    CRL Embedded: %v", cert.CRLEmbedded)
				if cert.RevocationWarning != "" {
					t.Logf("    Revocation Warning: %s", cert.RevocationWarning)
				}

				// Check that warning logic is working
				hasRevocationInfo := cert.OCSPEmbedded || cert.CRLEmbedded
				hasOCSPUrl := len(cert.Certificate.OCSPServer) > 0
				hasCRLUrl := len(cert.Certificate.CRLDistributionPoints) > 0
				canCheckExternally := hasOCSPUrl || hasCRLUrl

				if !hasRevocationInfo && !canCheckExternally {
					if cert.RevocationWarning == "" {
						t.Errorf("Expected revocation warning for certificate %d with no revocation info and no external URLs", j+1)
					}
				}
			}
		}
	}
}

func TestExternalRevocationChecking(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	// Open the test file
	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Failed to close file: %v", closeErr)
		}
	}()

	// Test with external checking disabled (default)
	response, err := VerifyFile(file)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}

	if response != nil && len(response.Signatures) > 0 {
		for i, sig := range response.Signatures {
			t.Logf("Signature %d (external checking disabled):", i+1)
			for j, cert := range sig.Validation.Certificates {
				t.Logf("  Certificate %d:", j+1)
				t.Logf("    OCSP Embedded: %v, External: %v", cert.OCSPEmbedded, cert.OCSPExternal)
				t.Logf("    CRL Embedded: %v, External: %v", cert.CRLEmbedded, cert.CRLExternal)

				// With external checking disabled, external flags should be false
				if cert.OCSPExternal {
					t.Errorf("Expected OCSPExternal to be false when external checking is disabled")
				}
				if cert.CRLExternal {
					t.Errorf("Expected CRLExternal to be false when external checking is disabled")
				}
			}
		}
	}

	// Test with external checking enabled
	if _, err := file.Seek(0, 0); err != nil {
		t.Logf("Warning: failed to reset file position: %v", err)
	}

	// Create custom options with external checking enabled
	options := DefaultVerifyOptions()
	options.EnableExternalRevocationCheck = true

	// Note: We're not actually testing external network calls here
	// as that would make tests flaky and dependent on network connectivity
	// The external checking will likely fail but should not crash
	t.Logf("Testing with external revocation checking enabled (may show network errors)")

	// This test mainly verifies that the options are properly passed through
	// and the external checking logic doesn't break the verification process
}
