package pdfsign_test

import (
	"testing"

	"github.com/digitorus/pdfsign"
)

func TestVerify_Execute_NoFile(t *testing.T) {
	// Test behavior when document has no reader (dummy doc)
	doc := &pdfsign.Document{} // initialized without OpenFile

	result := doc.Verify()
	if result.Err() == nil {
		t.Error("Expected error when verifying uninitialized document")
	}
}

// Integration verification tests for specific options are covered in pdf_test.go
