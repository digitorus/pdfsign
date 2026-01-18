package pdfsign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

// Helper to open test form
func openTestForm(t *testing.T) *Document {
	path := filepath.Join("testfiles", "testfile_form.pdf")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("skipping: %s not found", path)
	}
	doc, err := OpenFile(path)
	if err != nil {
		t.Fatalf("failed to open form: %v", err)
	}
	return doc
}

func TestForm_ListFields(t *testing.T) {
	doc := openTestForm(t)
	fields := doc.FormFields()

	if len(fields) == 0 {
		t.Fatal("expected fields in testfile_form.pdf")
	}

	// Just log them for debugging/verification during dev
	var names []string
	for _, f := range fields {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	t.Logf("Found fields: %v", names)
}

func TestForm_Lifecycle(t *testing.T) {
	// 1. Open and Inspect
	doc := openTestForm(t)
	fields := doc.FormFields()
	if len(fields) == 0 {
		t.Skip("no fields to test")
	}

	targetField := fields[0].Name
	t.Logf("Testing on field: %s", targetField)

	// 2. Set Value
	newValue := "Test Value 123"
	if err := doc.SetField(targetField, newValue); err != nil {
		t.Fatalf("SetField failed: %v", err)
	}

	// 3. Sign and Write (to apply changes)
	// We need valid certs to sign
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Form User")
	output := bytes.NewBuffer(nil)

	doc.Sign(key, cert).Reason("Form Test")
	if _, err := doc.Write(output); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// 4. Re-open and Verify
	// We need to write to a temp file to re-open with OpenFile (which takes path)
	// Or we can use filebuffer logic if exposed? OpenFile takes string path.
	// So write to temp file.
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "signed_form.pdf")
	if err := os.WriteFile(outPath, output.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	doc2, err := OpenFile(outPath)
	if err != nil {
		t.Fatalf("Failed to open signed file: %v", err)
	}

	// Verify value
	fields2 := doc2.FormFields()
	var found bool
	var foundNames []string
	for _, f := range fields2 {
		foundNames = append(foundNames, f.Name)
		if f.Name == targetField {
			found = true
			if f.Value != newValue {
				t.Errorf("Expected value %q, got %q", newValue, f.Value)
			}
			break
		}
	}
	if !found {
		t.Errorf("Field %s disappeared. Found fields: %v", targetField, foundNames)
	}

	// 5. Update Value
	updatedValue := "Updated Value 456"
	if err := doc2.SetField(targetField, updatedValue); err != nil {
		t.Fatal(err)
	}
	out2 := bytes.NewBuffer(nil)
	doc2.Sign(key, cert) // Re-sign
	if _, err := doc2.Write(out2); err != nil {
		t.Fatal(err)
	}

	// Check update
	outPath2 := filepath.Join(tmpDir, "signed_form_2.pdf")
	if err := os.WriteFile(outPath2, out2.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	doc3, _ := OpenFile(outPath2)
	for _, f := range doc3.FormFields() {
		if f.Name == targetField {
			if f.Value != updatedValue {
				t.Errorf("Expected updated value %q, got %q", updatedValue, f.Value)
			}
		}
	}

	// 6. Unset (Clear) Value - usually setting empty string
	if err := doc3.SetField(targetField, ""); err != nil {
		t.Fatal(err)
	}
	out3 := bytes.NewBuffer(nil)
	doc3.Sign(key, cert)
	if _, err := doc3.Write(out3); err != nil {
		t.Fatal(err)
	}

	outPath3 := filepath.Join(tmpDir, "signed_form_3.pdf")
	if err := os.WriteFile(outPath3, out3.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	doc4, _ := OpenFile(outPath3)
	for _, f := range doc4.FormFields() {
		if f.Name == targetField {
			if f.Value != "" {
				t.Errorf("Expected empty value, got %q", f.Value)
			}
		}
	}
}

func TestForm_Permissions(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Perm User")
	doc := openTestForm(t)
	fields := doc.FormFields()
	if len(fields) == 0 {
		t.Skip("no fields")
	}
	// targetField not needed here

	// Case 1: Sign with No Changes Allowed
	outNoChanges := bytes.NewBuffer(nil)
	doc.Sign(key, cert).
		Type(CertificationSignature).
		Permission(NoChanges).
		Reason("No Changes")

	if _, err := doc.Write(outNoChanges); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Reset doc for writing?
	// The document object accumulates pending signs.
	// To test clean state, open fresh doc.
}

func TestForm_Permissions_Implementation(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Perm Impl User")

	// Helper to create a signed doc with specific permissions
	createSigned := func(perm Permission) string {
		doc := openTestForm(t)
		out := bytes.NewBuffer(nil)

		doc.Sign(key, cert).
			Type(CertificationSignature).
			Permission(perm).
			Reason("Permission Test")

		if _, err := doc.Write(out); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if out.Len() == 0 {
			t.Fatal("Output is empty")
		}
		t.Logf("Created signed file size: %d", out.Len())

		tmp := filepath.Join(t.TempDir(), fmt.Sprintf("perm_%d.pdf", perm))
		if err := os.WriteFile(tmp, out.Bytes(), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		return tmp
	}

	// 1. Test DoNotAllowAnyChanges
	path1 := createSigned(NoChanges)

	// Open and Modify
	doc1, _ := OpenFile(path1)
	if err := doc1.SetField("Given Name Text Box", "Illegal Change"); err != nil {
		t.Fatal(err)
	}
	out1Mod := bytes.NewBuffer(nil)

	// We must sign to write changes (library limitation/feature)
	doc1.Sign(key, cert).Reason("Attempted Modification")

	if _, err := doc1.Write(out1Mod); err != nil {
		t.Fatal(err)
	}

	// Verify the original signature in the modified document
	doc1Mod, err := Open(bytes.NewReader(out1Mod.Bytes()), int64(out1Mod.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	results := doc1Mod.Verify()
	if results.Err() != nil {
		t.Logf("Verify error (unexpected): %v", results.Err())
	}

	if len(results.Signatures()) == 0 {
		t.Fatal("No signatures found")
	}

	if results.Signatures()[0].Valid {
		t.Fatal("Signature should be invalid because of disallowed changes (DocMDP P=1 detected)")
	}

	// 2. Test AllowFillingExistingFormFields
	path2 := createSigned(AllowFormFilling)

	doc2, _ := OpenFile(path2)
	if err := doc2.SetField("Given Name Text Box", "Legal Change"); err != nil {
		t.Fatal(err)
	}
	out2Mod := bytes.NewBuffer(nil)
	doc2.Sign(key, cert).Reason("Legal Modification")
	_, _ = doc2.Write(out2Mod)

	doc2Mod, _ := Open(bytes.NewReader(out2Mod.Bytes()), int64(out2Mod.Len()))
	results2 := doc2Mod.Verify()

	if len(results2.Signatures()) == 0 {
		t.Fatal("No signatures found")
	}

	if !results2.Signatures()[0].Valid {
		t.Errorf("Signature marked invalid despite allowed changes (DocMDP P=2). Valid: %v, Errors: %v", results2.Signatures()[0].Valid, results2.Signatures()[0].Errors)
	} else {
		// Retain successful artifact for manual inspection
		successDir := filepath.Join("testfiles", "success")
		_ = os.MkdirAll(successDir, 0755)
		if err := os.WriteFile(filepath.Join(successDir, "form_filled_signed.pdf"), out2Mod.Bytes(), 0644); err != nil {
			t.Logf("Failed to save success artifact: %v", err)
		}
	}
}
