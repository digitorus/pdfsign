package verify

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDocumentInfoParsing(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")
	
	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist", testFilePath)
	}

	file, err := os.Open(testFilePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	response, err := File(file)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}

	// Test document info fields
	info := response.DocumentInfo
	
	// Check that at least some fields are populated or logged
	fields := map[string]interface{}{
		"Author":       info.Author,
		"Creator":      info.Creator,
		"Producer":     info.Producer,
		"Title":        info.Title,
		"Subject":      info.Subject,
		"Hash":         info.Hash,
		"Name":         info.Name,
		"Permission":   info.Permission,
		"Pages":        info.Pages,
		"Keywords":     info.Keywords,
		"CreationDate": info.CreationDate,
		"ModDate":      info.ModDate,
	}
	
	t.Log("Document Information Fields:")
	for field, value := range fields {
		switch v := value.(type) {
		case string:
			if v != "" {
				t.Logf("  %s: %s", field, v)
			}
		case int:
			if v > 0 {
				t.Logf("  %s: %d", field, v)
			}
		case []string:
			if len(v) > 0 {
				t.Logf("  %s: %v", field, v)
			}
		case time.Time:
			if !v.IsZero() {
				t.Logf("  %s: %s", field, v.Format(time.RFC3339))
			}
		}
	}
}
