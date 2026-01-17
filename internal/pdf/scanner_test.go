package pdf_test

import (
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestScanExistingFonts(t *testing.T) {
	// Use a known test file with fonts
	file := testpki.GetTestFile("testfiles/testfile30.pdf")
	if _, err := os.Stat(file); os.IsNotExist(err) {
		t.Skip("skipping test; testfile30.pdf not found")
	}

	doc, err := pdfsign.OpenFile(file)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	fonts := doc.Fonts()
	if fonts == nil {
		t.Fatal("Fonts() returned nil")
	}

	// testfile30.pdf is known to have fonts
	if len(fonts) == 0 {
		t.Error("Expected at least one font in testfile30.pdf, got 0")
	}

	t.Logf("Found %d existing fonts", len(fonts))
	for _, f := range fonts {
		if f.Name == "" {
			t.Error("Found font with empty name")
		}
		t.Logf(" - %s (Embedded: %v)", f.Name, f.Embedded)
	}
}
