package forms_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestForms_Setters(t *testing.T) {
	doc := &pdfsign.Document{}

	// Test SetField
	err := doc.SetField("test", "value")
	if err != nil {
		t.Errorf("SetField failed: %v", err)
	}

	// Test SetFields
	fields := map[string]any{
		"foo": "bar",
		"baz": 123,
	}
	err = doc.SetFields(fields)
	if err != nil {
		t.Errorf("SetFields failed: %v", err)
	}
}

func TestExploreForms(t *testing.T) {
	testDir := testpki.GetTestFile("testfiles")
	files, _ := os.ReadDir(testDir)
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".pdf" {
			path := filepath.Join(testDir, f.Name())
			doc, err := pdfsign.OpenFile(path)
			if err != nil {
				continue
			}
			fields := doc.FormFields()
			if len(fields) > 0 {
				t.Logf("File %s has %d fields", f.Name(), len(fields))
			}
		}
	}
}

func TestForms_WithRealFile(t *testing.T) {
	testFile := testpki.GetTestFile("testfiles/testfile30.pdf")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("testfile30.pdf not found")
	}

	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	fields := doc.FormFields()
	if len(fields) == 0 {
		t.Error("Expected fields in testfile30.pdf, found none")
	}

	// Test field setting on real file
	if err := doc.SetField(fields[0].Name, "Updated Value"); err != nil {
		t.Errorf("Failed to set field: %v", err)
	}

	// So we must sign to apply fields.
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Forms User")
	doc.Sign(key, cert).Reason("Form Test")

	out := new(bytes.Buffer)
	if _, err := doc.Write(out); err != nil {
		t.Errorf("Failed to write document: %v", err)
	}
}

func TestForms_Negatives(t *testing.T) {
	testFile := testpki.GetTestFile("testfiles/testfile20.pdf") // File with no fields
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	doc, _ := pdfsign.OpenFile(testFile)

	// Set non-existent field
	if err := doc.SetField("GhostField", "Boo"); err != nil {
		t.Logf("SetField error (expectedly ignored in test flow): %v", err)
	}
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Ghost User")
	doc.Sign(key, cert).Reason("Form Fail")

	if _, err := doc.Write(new(bytes.Buffer)); err == nil {
		t.Error("Expected error when setting non-existent field")
	}
}
