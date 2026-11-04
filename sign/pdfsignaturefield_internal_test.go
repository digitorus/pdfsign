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
