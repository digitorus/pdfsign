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
	defer file.Close()

	// Verify the file
	response, err := File(file)
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
	if len(response.Signers) == 0 {
		t.Fatal("No signers found in the document")
	}

	t.Logf("Found %d signer(s)", len(response.Signers))

	// Validate each signer
	for i, signer := range response.Signers {
		t.Logf("Signer %d:", i+1)
		t.Logf("  Name: %s", signer.Name)
		t.Logf("  Reason: %s", signer.Reason)
		t.Logf("  Location: %s", signer.Location)
		t.Logf("  ContactInfo: %s", signer.ContactInfo)
		t.Logf("  ValidSignature: %t", signer.ValidSignature)
		t.Logf("  TrustedIssuer: %t", signer.TrustedIssuer)
		t.Logf("  RevokedCertificate: %t", signer.RevokedCertificate)
		t.Logf("  Certificates count: %d", len(signer.Certificates))

		// Check if we have certificates
		if len(signer.Certificates) == 0 {
			t.Errorf("Signer %d has no certificates", i+1)
		}

		// Validate certificates
		for j, cert := range signer.Certificates {
			if cert.Certificate == nil {
				t.Errorf("Signer %d, certificate %d is nil", i+1, j+1)
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
		if signer.TimeStamp != nil {
			t.Logf("  Timestamp: %s", signer.TimeStamp.Time)
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
	defer file.Close()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	// Verify using Reader
	response, err := Reader(file, fileInfo.Size())
	if err != nil {
		t.Fatalf("Failed to verify file with Reader: %v", err)
	}

	// Basic validation
	if response == nil {
		t.Fatal("Response is nil")
	}

	if len(response.Signers) == 0 {
		t.Fatal("No signers found in the document")
	}

	t.Logf("Reader test: Found %d signer(s)", len(response.Signers))
}

func TestFileWithInvalidFile(t *testing.T) {
	// Create a temporary invalid file
	tmpFile, err := os.CreateTemp("", "invalid_*.pdf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

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
	_, err = File(tmpFile)
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
	defer file.Close()

	// This might fail if the file is unsigned
	response, err := File(file)
	if err != nil {
		// This is expected for unsigned PDFs
		t.Logf("Expected error for unsigned PDF: %v", err)
		return
	}

	// If it succeeds, log the results
	if response != nil {
		t.Logf("Unsigned PDF test: Found %d signer(s)", len(response.Signers))
	}
}
