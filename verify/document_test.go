package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDocumentInfoParsing(t *testing.T) {
	testFilePath := filepath.Join("..", "testfiles", "testfile30.pdf")
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
	response, err := VerifyFile(file)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}
	info := response.DocumentInfo
	fields := map[string]interface{}{
		"Author":   info.Author,
		"Creator":  info.Creator,
		"Producer": info.Producer,
		"Title":    info.Title,
		"Subject":  info.Subject,
		"Hash":     info.Hash,
		"Name":     info.Name,
	}
	for k, v := range fields {
		if v == "" {
			t.Logf("Field %s is empty", k)
		}
	}
	if info.Pages == 0 {
		t.Error("Pages field is zero")
	}
}
