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

// writePDFWithCatalog builds a minimal one-page PDF whose document catalog is
// extended with the given raw entries, followed by any extra objects (numbered
// from 6), and returns its path. Object 5 is a bare signature dictionary that
// the catalog entries can point at.
func writePDFWithCatalog(t *testing.T, catalogEntries string, extraObjects ...string) string {
	t.Helper()

	content := "BT ET\n"
	objects := append([]string{
		"<< /Type /Catalog /Pages 2 0 R " + catalogEntries + " >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"<< /Type /Sig /Filter /Adobe.PPKLite >>",
	}, extraObjects...)

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

	path := filepath.Join(t.TempDir(), "catalog.pdf")
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
	t.Cleanup(func() { _ = inputFile.Close() })

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

// signFileAs signs input into a temporary file with the given certificate type
// and returns the output path and the signing error.
func signFileAs(t *testing.T, input string, certType CertType) (string, error) {
	t.Helper()

	certificate, privateKey := LoadCertificateAndKey(t)
	output := filepath.Join(t.TempDir(), "signed.pdf")
	err := SignFile(input, output, SignData{
		Signature: SignDataSignature{
			CertType:   certType,
			DocMDPPerm: DoNotAllowAnyChangesPerms,
		},
		Signer:      privateKey,
		Certificate: certificate,
	})
	return output, err
}

// readCatalog opens a signed file and returns its document catalog.
func readCatalog(t *testing.T, path string) pdf.Value {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })

	finfo, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	rdr, err := pdf.NewReader(f, finfo.Size())
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return rdr.Trailer().Key("Root")
}

// TestCreateCatalogPermsDocMDP covers ISO 32000-1 12.8.2.2: the /Perms /DocMDP
// entry in the document catalog is what makes a reader treat a signature as a
// certification signature and apply its /P permission level. The /Reference
// transform in the signature dictionary alone is not enough.
func TestCreateCatalogPermsDocMDP(t *testing.T) {
	t.Run("a usage rights signature writes /Perms /UR3", func(t *testing.T) {
		catalog, err := catalogForFile(t, "../testfiles/testfile20.pdf", UsageRightsSignature, 42)
		if err != nil {
			t.Fatalf("createCatalog: %v", err)
		}
		if got := string(catalog); !strings.Contains(got, "/UR3 42 0 R") || strings.Contains(got, "/DocMDP") {
			t.Errorf("usage rights catalog lacks /Perms /UR3 or carries /DocMDP:\n%s", got)
		}
	})

	t.Run("approval and timestamp signatures write no /Perms", func(t *testing.T) {
		for _, certType := range []CertType{ApprovalSignature, TimeStampSignature} {
			catalog, err := catalogForFile(t, "../testfiles/testfile20.pdf", certType, 42)
			if err != nil {
				t.Fatalf("%s: createCatalog: %v", certType, err)
			}
			if strings.Contains(string(catalog), "/Perms") {
				t.Errorf("%s wrote a catalog /Perms entry:\n%s", certType, catalog)
			}
		}
	})

	t.Run("an inline /Perms keeps its entries", func(t *testing.T) {
		file := writePDFWithCatalog(t, "/Perms << /UR3 5 0 R >>")

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

	t.Run("an indirect /Perms keeps its direct values inline", func(t *testing.T) {
		// Direct values read from an indirect /Perms carry that object's
		// pointer (6 0 R here); they must be written as values, not as
		// references back to the superseded /Perms object.
		file := writePDFWithCatalog(t, "/Perms 6 0 R", "<< /UR3 5 0 R /Custom 1 >>")

		catalog, err := catalogForFile(t, file, CertificationSignature, 9)
		if err != nil {
			t.Fatalf("createCatalog: %v", err)
		}

		got := string(catalog)
		if strings.Contains(got, "6 0 R") {
			t.Errorf("a /Perms entry was written as a reference to the old /Perms object:\n%s", got)
		}
		for _, want := range []string{"/UR3 5 0 R", "/Custom 1", "/DocMDP 9 0 R"} {
			if !strings.Contains(got, want) {
				t.Errorf("catalog is missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("copied strings and names cannot end their own token", func(t *testing.T) {
		// The reader decodes these escapes, so writing the decoded bytes
		// back verbatim would let a value close the dictionary early and
		// continue as catalog structure.
		file := writePDFWithCatalog(t, `/Perms << /UR3 5 0 R /Note (a\)/DocMDP 5 0 R\() /We#20ird#2Fkey /na#20me >>`)

		output, err := signFileAs(t, file, CertificationSignature)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		perms := readCatalog(t, output).Key("Perms")
		if got, want := perms.RawString(), ""; got != want {
			t.Errorf("/Perms is not a dictionary any more: %q", got)
		}
		if got, want := perms.Key("Note").RawString(), "a)/DocMDP 5 0 R("; got != want {
			t.Errorf("/Perms /Note = %q, want %q", got, want)
		}
		if got, want := perms.Key("We ird/key").Name(), "na me"; got != want {
			t.Errorf("/Perms /We ird/key = %q, want %q", got, want)
		}
		if got := perms.Key("DocMDP").Key("Type").Name(); got != "Sig" {
			t.Errorf("/Perms /DocMDP points at a /Type /%s object, want /Sig", got)
		}
		if got := perms.Key("DocMDP").Key("Reference").Index(0).Key("TransformMethod").Name(); got != "DocMDP" {
			t.Errorf("/Perms /DocMDP does not point at the new certification signature")
		}
	})
}

// TestCertificationSignatureValidation covers the documents that cannot take a
// certification signature: only one DocMDP signature is permitted, and it has
// to be the first signature in the document.
func TestCertificationSignatureValidation(t *testing.T) {
	t.Run("an already certified document is rejected", func(t *testing.T) {
		file := writePDFWithCatalog(t, "/Perms << /DocMDP 5 0 R >>")

		if _, err := signFileAs(t, file, CertificationSignature); err == nil {
			t.Fatal("expected an error when certifying an already certified document")
		} else if !strings.Contains(err.Error(), "already certified") {
			t.Errorf("unexpected error: %v", err)
		}

		// The same document can still take an approval signature, which
		// leaves the existing /Perms untouched.
		output, err := signFileAs(t, file, ApprovalSignature)
		if err != nil {
			t.Fatalf("approval signature: %v", err)
		}
		if got := readCatalog(t, output).Key("Perms").Key("DocMDP").Key("Type").Name(); got != "Sig" {
			t.Errorf("approval signature did not preserve the existing /Perms /DocMDP, got /Type /%s", got)
		}
	})

	t.Run("a /DocMDP that cannot be resolved still counts", func(t *testing.T) {
		// Object 99 does not exist, so the entry resolves to null; it would
		// otherwise be copied next to the new /DocMDP as a duplicate key.
		file := writePDFWithCatalog(t, "/Perms << /DocMDP 99 0 R >>")

		if _, err := signFileAs(t, file, CertificationSignature); err == nil {
			t.Fatal("expected an error for a /Perms with a dangling /DocMDP")
		} else if !strings.Contains(err.Error(), "already certified") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("a /Perms that cannot be read is rejected", func(t *testing.T) {
		for name, entries := range map[string]string{
			"not a dictionary":   "/Perms 5",
			"dangling reference": "/Perms 99 0 R",
		} {
			t.Run(name, func(t *testing.T) {
				file := writePDFWithCatalog(t, entries)

				if _, err := signFileAs(t, file, CertificationSignature); err == nil {
					t.Fatal("expected an error")
				} else if !strings.Contains(err.Error(), "could not be read as a dictionary") {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("an already signed document is rejected", func(t *testing.T) {
		signed, err := signFileAs(t, "../testfiles/testfile20.pdf", ApprovalSignature)
		if err != nil {
			t.Fatalf("approval signature: %v", err)
		}

		if _, err := signFileAs(t, signed, CertificationSignature); err == nil {
			t.Fatal("expected an error when certifying an already signed document")
		} else if !strings.Contains(err.Error(), "first signature") {
			t.Errorf("unexpected error: %v", err)
		}

		// A second approval signature is fine.
		if _, err := signFileAs(t, signed, ApprovalSignature); err != nil {
			t.Fatalf("second approval signature: %v", err)
		}
	})

	t.Run("a signed field below a parent field is found", func(t *testing.T) {
		// Object 5 is a bare signature dictionary; object 6 is a parent
		// field whose /Kids hold the signed field, as hierarchical field
		// names ("form.sig1") are laid out.
		for name, objects := range map[string][]string{
			"FT on the signed field": {
				"<< /T (form) /Kids [7 0 R] >>",
				"<< /Parent 6 0 R /T (sig1) /FT /Sig /V 5 0 R >>",
			},
			"FT inherited from the parent": {
				"<< /T (form) /FT /Sig /Kids [7 0 R] >>",
				"<< /Parent 6 0 R /T (sig1) /V 5 0 R >>",
			},
			"Kids that loop back": {
				"<< /T (form) /Kids [7 0 R] >>",
				"<< /Parent 6 0 R /T (inner) /Kids [6 0 R 8 0 R] >>",
				"<< /Parent 7 0 R /T (sig1) /FT /Sig /V 5 0 R >>",
			},
		} {
			t.Run(name, func(t *testing.T) {
				file := writePDFWithCatalog(t, "/AcroForm << /Fields [6 0 R] /SigFlags 3 >>", objects...)

				if _, err := signFileAs(t, file, CertificationSignature); err == nil {
					t.Fatal("expected an error when certifying a document with a nested signed field")
				} else if !strings.Contains(err.Error(), "first signature") {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("widget kids without /T belong to their signed field", func(t *testing.T) {
		file := writePDFWithCatalog(t, "/AcroForm << /Fields [6 0 R] /SigFlags 3 >>",
			"<< /T (sig1) /FT /Sig /V 5 0 R /Kids [7 0 R] >>",
			"<< /Parent 6 0 R /Subtype /Widget /Rect [0 0 1 1] >>")

		if _, err := signFileAs(t, file, CertificationSignature); err == nil {
			t.Fatal("expected an error when certifying a document whose signed field has widget kids")
		} else if !strings.Contains(err.Error(), "first signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("a usage rights signature does not have to be first", func(t *testing.T) {
		signed, err := signFileAs(t, "../testfiles/testfile20.pdf", ApprovalSignature)
		if err != nil {
			t.Fatalf("approval signature: %v", err)
		}

		output, err := signFileAs(t, signed, UsageRightsSignature)
		if err != nil {
			t.Fatalf("usage rights signature: %v", err)
		}
		ur3 := readCatalog(t, output).Key("Perms").Key("UR3")
		if got := ur3.Key("Type").Name(); got != "Sig" {
			t.Errorf("/Perms /UR3 points at a /Type /%s object, want /Sig", got)
		}
		if got := ur3.Key("Reference").Index(0).Key("TransformMethod").Name(); got != "UR3" {
			t.Errorf("/Perms /UR3 does not point at the usage rights signature (transform /%s)", got)
		}

		// Only one usage rights signature can be referenced from /Perms.
		if _, err := signFileAs(t, output, UsageRightsSignature); err == nil {
			t.Fatal("expected an error when adding a second usage rights signature")
		} else if !strings.Contains(err.Error(), "already contains /UR3") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("an unsigned signature field does not count", func(t *testing.T) {
		file := writePDFWithCatalog(t, "/AcroForm << /Fields [6 0 R] /SigFlags 3 >>",
			"<< /T (sig1) /FT /Sig >>")

		if _, err := signFileAs(t, file, CertificationSignature); err != nil {
			t.Fatalf("an empty signature field must not block certification: %v", err)
		}
	})
}

// TestSignedFilePermsDocMDP signs a file end to end and resolves the catalog
// /Perms /DocMDP reference through the PDF reader, which is how a conforming
// reader finds the certification signature.
func TestSignedFilePermsDocMDP(t *testing.T) {
	for _, tc := range []struct {
		certType  CertType
		wantPerms bool
	}{
		{CertificationSignature, true},
		{ApprovalSignature, false},
	} {
		t.Run(tc.certType.String(), func(t *testing.T) {
			output, err := signFileAs(t, "../testfiles/testfile20.pdf", tc.certType)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			perms := readCatalog(t, output).Key("Perms")
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

// TestFetchExistingSignatures checks the field tree walk shared with
// hasSignedField: terminal signature fields are found wherever they sit, with
// /FT inherited from a parent field, while widget kids are not counted as
// fields of their own.
func TestFetchExistingSignatures(t *testing.T) {
	for name, tc := range map[string]struct {
		objects []string
		want    []uint32
	}{
		"top-level field": {
			objects: []string{"<< /T (sig1) /FT /Sig /V 5 0 R >>"},
			want:    []uint32{6},
		},
		"field below a parent with inherited /FT": {
			objects: []string{
				"<< /T (form) /FT /Sig /Kids [7 0 R] >>",
				"<< /Parent 6 0 R /T (sig1) /V 5 0 R >>",
			},
			want: []uint32{7},
		},
		"widget kids are not fields": {
			objects: []string{
				"<< /T (sig1) /FT /Sig /V 5 0 R /Kids [7 0 R 8 0 R] >>",
				"<< /Parent 6 0 R /Subtype /Widget /Rect [0 0 1 1] >>",
				"<< /Parent 6 0 R /Subtype /Widget /Rect [1 1 2 2] >>",
			},
			want: []uint32{6},
		},
		"kids that loop back": {
			objects: []string{
				"<< /T (form) /Kids [7 0 R] >>",
				"<< /Parent 6 0 R /T (inner) /Kids [6 0 R 8 0 R] >>",
				"<< /Parent 7 0 R /T (sig1) /FT /Sig >>",
			},
			want: []uint32{8},
		},
	} {
		t.Run(name, func(t *testing.T) {
			file := writePDFWithCatalog(t, "/AcroForm << /Fields [6 0 R] /SigFlags 3 >>", tc.objects...)

			inputFile, err := os.Open(file)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = inputFile.Close() }()
			finfo, err := inputFile.Stat()
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			rdr, err := pdf.NewReader(inputFile, finfo.Size())
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			context := SignContext{PDFReader: rdr}
			signatures, err := context.fetchExistingSignatures()
			if err != nil {
				t.Fatalf("fetchExistingSignatures: %v", err)
			}
			var got []uint32
			for _, sig := range signatures {
				got = append(got, sig.objectId)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("signature fields = %v, want %v", got, tc.want)
			}
		})
	}
}
