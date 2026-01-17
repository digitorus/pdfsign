package extract_test

import (
	"io"
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestSignatureExtraction(t *testing.T) {
	// Setup PKI and Sign a file for testing
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer() // Required for IssueLeaf
	defer pki.Close()

	priv, cert := pki.IssueLeaf("Test Extraction")

	inputFile := testpki.GetTestFile("testfiles/testfile12.pdf") // Use the clean file

	// Create temp file for output
	tf, err := os.CreateTemp("", "testfile12_extracted_*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	outputFile := tf.Name()
	_ = tf.Close()
	defer func() { _ = os.Remove(outputFile) }()

	doc, err := pdfsign.OpenFile(inputFile)
	if err != nil {
		t.Fatalf("failed to open input file: %v", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	defer func() { _ = f.Close() }()

	doc.Sign(priv, cert)
	if _, err := doc.Write(f); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Now Extraction Test
	verifyDoc, err := pdfsign.OpenFile(outputFile)
	if err != nil {
		t.Fatalf("failed to open signed file: %v", err)
	}

	found := false
	for sig, err := range verifyDoc.Signatures() {
		if err != nil {
			t.Fatalf("Iteration error: %v", err)
		}
		found = true

		// Test lazy properties
		name := sig.Name()
		if name == "" {
			t.Log("Note: Extracted signature name is empty")
		}

		contents := sig.Contents()
		if len(contents) == 0 {
			t.Errorf("Extracted signature has empty contents")
		}

		// Filter
		if sig.Filter() != "Adobe.PPKLite" {
			t.Errorf("Extracted signature has unexpected filter: %s", sig.Filter())
		}

		// ByteRange
		br := sig.ByteRange()
		if len(br) == 0 {
			t.Errorf("ByteRange should not be empty")
		}

		// SignedData
		reader, err := sig.SignedData()
		if err != nil {
			t.Errorf("SignedData() failed: %v", err)
		}

		data, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("Failed to read SignedData: %v", err)
		}
		if len(data) == 0 {
			t.Errorf("SignedData returned empty bytes")
		}

		t.Logf("Extraction successful: %s (%d bytes)", name, len(contents))
	}

	if !found {
		t.Error("No signatures found in signed document")
	}
}
