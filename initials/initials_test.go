package initials_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestInitials_Execution(t *testing.T) {
	testFile := testpki.GetTestFile("testfiles/testfile20.pdf")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	app := pdfsign.NewAppearance(50, 20)
	app.Text("TEST LONG TEXT").AutoScale().Center()

	// Do NOT exclude page 1, so the logic actually runs
	doc.AddInitials(app).Position(pdfsign.BottomRight, 10, 10)

	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Initials User")
	doc.Sign(key, cert).Reason("Initials Test")

	out := new(bytes.Buffer)
	if _, err := doc.Write(out); err != nil {
		t.Errorf("Failed to write document with initials: %v", err)
	}
}
