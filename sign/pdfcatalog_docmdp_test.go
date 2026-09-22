package sign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

// writePDFWithCatalogPerms builds a minimal PDF whose document catalog already
// carries the given raw /Perms dictionary, and returns its path.
func writePDFWithCatalogPerms(t *testing.T, perms string) string {
	t.Helper()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R " + perms + " >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
		"<< /Length 8 >>\nstream\nBT ET\nendstream",
		"<< /Type /Sig /Filter /Adobe.PPKLite >>",
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)

	path := filepath.Join(t.TempDir(), "perms.pdf")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write test PDF: %v", err)
	}
	return path
}

// catalogForFile runs createCatalog over the given file for the given
// certificate type, with a pinned signature object number.
func catalogForFile(t *testing.T, file string, certType CertType, sigObjectId uint32) ([]byte, error) {
	t.Helper()

	inputFile, err := os.Open(file)
	if err != nil {
		t.Fatalf("open %s: %v", file, err)
	}
	t.Cleanup(func() { inputFile.Close() })

	finfo, err := inputFile.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", file, err)
	}

	rdr, err := pdf.NewReader(inputFile, finfo.Size())
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}

	context := SignContext{
		PDFReader: rdr,
		InputFile: inputFile,
		VisualSignData: VisualSignData{
			objectId: uint32(rdr.XrefInformation.ItemCount),
		},
		SignData: SignData{
			Signature: SignDataSignature{
				CertType:   certType,
				DocMDPPerm: DoNotAllowAnyChangesPerms,
			},
			objectId: sigObjectId,
		},
	}

	return context.createCatalog()
}

// TestCreateCatalogPermsDocMDP covers ISO 32000-1 12.8.2.2: the /Perms /DocMDP
// entry in the document catalog is what makes a reader treat a signature as a
// certification signature and apply its /P permission level. The /Reference
// transform in the signature dictionary alone is not enough.
func TestCreateCatalogPermsDocMDP(t *testing.T) {
	t.Run("only a certification signature writes /Perms", func(t *testing.T) {
		for _, certType := range []CertType{ApprovalSignature, UsageRightsSignature, TimeStampSignature} {
			catalog, err := catalogForFile(t, "../testfiles/testfile20.pdf", certType, 42)
			if err != nil {
				t.Fatalf("%s: createCatalog: %v", certType, err)
			}
			if strings.Contains(string(catalog), "/Perms") {
				t.Errorf("%s wrote a catalog /Perms entry:\n%s", certType, catalog)
			}
		}
	})

	t.Run("existing /Perms entries are preserved", func(t *testing.T) {
		file := writePDFWithCatalogPerms(t, "/Perms << /UR3 5 0 R >>")

		catalog, err := catalogForFile(t, file, CertificationSignature, 9)
		if err != nil {
			t.Fatalf("createCatalog: %v", err)
		}

		got := string(catalog)
		if strings.Count(got, "/Perms") != 1 {
			t.Errorf("catalog does not contain exactly one /Perms key:\n%s", got)
		}
		if !strings.Contains(got, "/UR3 5 0 R") {
			t.Errorf("existing /Perms /UR3 entry was dropped:\n%s", got)
		}
		if !strings.Contains(got, "/DocMDP 9 0 R") {
			t.Errorf("catalog is missing /DocMDP 9 0 R:\n%s", got)
		}
	})

	t.Run("an already certified document is rejected", func(t *testing.T) {
		file := writePDFWithCatalogPerms(t, "/Perms << /DocMDP 5 0 R >>")

		if _, err := catalogForFile(t, file, CertificationSignature, 9); err == nil {
			t.Fatal("expected an error when certifying an already certified document")
		} else if !strings.Contains(err.Error(), "already certified") {
			t.Errorf("unexpected error: %v", err)
		}

		// The same document can still take an approval signature, which
		// leaves the existing /Perms untouched.
		catalog, err := catalogForFile(t, file, ApprovalSignature, 9)
		if err != nil {
			t.Fatalf("approval signature: %v", err)
		}
		if !strings.Contains(string(catalog), "/Perms <</DocMDP 5 0 R>>") {
			t.Errorf("approval signature did not preserve the existing /Perms:\n%s", catalog)
		}
	})

	t.Run("a malformed /Perms is rejected", func(t *testing.T) {
		file := writePDFWithCatalogPerms(t, "/Perms 5")

		if _, err := catalogForFile(t, file, CertificationSignature, 9); err == nil {
			t.Fatal("expected an error for a non-dictionary /Perms")
		} else if !strings.Contains(err.Error(), "not a dictionary") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestSignedFilePermsDocMDP signs a file end to end and resolves the catalog
// /Perms /DocMDP reference through the PDF reader, which is how a conforming
// reader finds the certification signature.
func TestSignedFilePermsDocMDP(t *testing.T) {
	certificate, privateKey := LoadCertificateAndKey(t)

	for _, tc := range []struct {
		certType  CertType
		wantPerms bool
	}{
		{CertificationSignature, true},
		{ApprovalSignature, false},
	} {
		t.Run(tc.certType.String(), func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "signed.pdf")
			if err := SignFile("../testfiles/testfile20.pdf", outputPath, SignData{
				Signature: SignDataSignature{
					CertType:   tc.certType,
					DocMDPPerm: DoNotAllowAnyChangesPerms,
				},
				Signer:      privateKey,
				Certificate: certificate,
			}); err != nil {
				t.Fatalf("sign: %v", err)
			}

			outputFile, err := os.Open(outputPath)
			if err != nil {
				t.Fatalf("open signed file: %v", err)
			}
			defer outputFile.Close()

			finfo, err := outputFile.Stat()
			if err != nil {
				t.Fatalf("stat signed file: %v", err)
			}

			rdr, err := pdf.NewReader(outputFile, finfo.Size())
			if err != nil {
				t.Fatalf("read signed file: %v", err)
			}

			perms := rdr.Trailer().Key("Root").Key("Perms")
			if !tc.wantPerms {
				if !perms.IsNull() {
					t.Fatalf("%s wrote a catalog /Perms entry", tc.certType)
				}
				return
			}

			if perms.IsNull() {
				t.Fatal("certification signature has no catalog /Perms; readers treat it as an approval signature")
			}

			// A dangling or mistargeted reference is worse than none, so
			// follow it and check it lands on the signature dictionary.
			docMDP := perms.Key("DocMDP")
			if docMDP.IsNull() {
				t.Fatal("catalog /Perms carries no /DocMDP entry")
			}
			if got := docMDP.Key("Type").Name(); got != "Sig" {
				t.Errorf("/Perms /DocMDP points at a /Type /%s object, want /Sig", got)
			}
			reference := docMDP.Key("Reference").Index(0)
			if got := reference.Key("TransformMethod").Name(); got != "DocMDP" {
				t.Errorf("signature /Reference /TransformMethod = /%s, want /DocMDP", got)
			}
			if got := reference.Key("TransformParams").Key("P").Int64(); got != int64(DoNotAllowAnyChangesPerms) {
				t.Errorf("/TransformParams /P = %d, want %d", got, DoNotAllowAnyChangesPerms)
			}
		})
	}
}
