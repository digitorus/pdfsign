package sign

import (
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpdf"
)

func TestExistingFieldInlineAndNull(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		objects      []string
		wantErr      bool
	}{
		{"inline in catalog", "[<< /FT /Sig /T (sig) >>]", nil, true},
		{"inline in indirect array", "4 0 R", []string{"[<< /FT /Sig /T (sig) >>]"}, true},
		{"explicit null", "[4 0 R]", []string{"<< /FT /Sig /T (sig) /V null >>"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := append([]string{"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields " + tc.fields + " /DA (/Helv 12 Tf) /NeedAppearances true >> >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"}, tc.objects...)
			ctx := &SignContext{PDFReader: testpdf.Reader(t, objects...), SignData: SignData{FieldName: "sig"}}
			field, err := ctx.findSignatureField("sig")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "direct object") {
					t.Fatalf("expected direct object rejection, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			update, err := ctx.createFilledSignatureField(field)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(update), "/V ") != 1 {
				t.Fatalf("duplicate value: %s", update)
			}
			catalog, err := ctx.createCatalog()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(catalog), "/DA (/Helv 12 Tf)") || !strings.Contains(string(catalog), "/NeedAppearances true") {
				t.Fatalf("lost form settings: %s", catalog)
			}
		})
	}
}

func TestExistingFieldKeepsIndirectAcroForm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		certType  CertType
		sigFlags  string
		wantFlags string
	}{
		{"approval merges flags", ApprovalSignature, "/SigFlags 1", "/SigFlags 3"},
		{"approval without flags", ApprovalSignature, "", "/SigFlags 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := []string{
				"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>",
				"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
				"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
				"<< /Fields 5 0 R /DA (/Helv 12 Tf) /DR << /Font << /Helv 7 0 R >> >> " + tc.sigFlags + " >>",
				"[6 0 R]",
				"<< /FT /Sig /T (sig) >>",
				"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
			}
			ctx := &SignContext{
				PDFReader: testpdf.Reader(t, objects...),
				SignData:  SignData{FieldName: "sig", Signature: SignDataSignature{CertType: tc.certType}},
			}
			if _, err := ctx.findSignatureField("sig"); err != nil {
				t.Fatal(err)
			}
			catalog, err := ctx.createCatalog()
			if err != nil {
				t.Fatal(err)
			}
			got := string(catalog)
			for _, want := range []string{"/Fields 5 0 R", "/DA (/Helv 12 Tf)", "/Helv 7 0 R", tc.wantFlags} {
				if !strings.Contains(got, want) {
					t.Errorf("catalog lacks %q: %s", want, got)
				}
			}
			if strings.Count(got, "/SigFlags") != 1 {
				t.Errorf("expected exactly one /SigFlags: %s", got)
			}
			if strings.Contains(got, "/AcroForm 4 0 R") {
				t.Errorf("AcroForm should be rewritten inline: %s", got)
			}
		})
	}
}
