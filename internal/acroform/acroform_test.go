package acroform

import (
	"fmt"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/testpdf"
)

// rootWithFields builds a document whose AcroForm /Fields array is
// fieldsArray (object 4 being the first extra object) and returns its catalog.
// Object 5 is a bare signature dictionary the fields can point at.
func rootWithFields(t *testing.T, fieldsArray string, objects ...string) pdf.Value {
	t.Helper()
	all := append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields " + fieldsArray + " /SigFlags 3 >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}, objects...)
	return testpdf.Reader(t, all...).Trailer().Key("Root")
}

// names collects the /T of every signature field the walk reports.
func names(root pdf.Value) []string {
	var got []string
	SignatureFields(root, func(field pdf.Value) bool {
		got = append(got, field.Key("T").Text())
		return true
	})
	return got
}

func TestSignatureFields(t *testing.T) {
	sig := "<< /Type /Sig /Filter /Adobe.PPKLite >>"

	for name, tc := range map[string]struct {
		fields  string
		objects []string
		want    []string
	}{
		"top-level fields in order": {
			fields:  "[4 0 R 6 0 R]",
			objects: []string{"<< /T (a) /FT /Sig /V 5 0 R >>", sig, "<< /T (b) /FT /Sig >>"},
			want:    []string{"a", "b"},
		},
		"direct dictionaries are each reported": {
			fields:  "[<< /T (a) /FT /Sig /V 5 0 R >> << /T (b) /FT /Sig /V 5 0 R >>]",
			objects: []string{"<< /T (unused) >>", sig},
			want:    []string{"a", "b"},
		},
		"/FT inherited from the parent": {
			fields:  "[4 0 R]",
			objects: []string{"<< /T (form) /FT /Sig /Kids [6 0 R] >>", sig, "<< /Parent 4 0 R /T (sig1) /V 5 0 R >>"},
			want:    []string{"sig1"},
		},
		"untitled nested field": {
			fields:  "[4 0 R]",
			objects: []string{"<< /T (form) /Kids [6 0 R] >>", sig, "<< /Parent 4 0 R /FT /Sig /V 5 0 R >>"},
			want:    []string{""},
		},
		"widget kids belong to their field": {
			fields: "[4 0 R]",
			objects: []string{
				"<< /T (sig1) /FT /Sig /V 5 0 R /Kids [6 0 R 7 0 R] >>", sig,
				"<< /Parent 4 0 R /Subtype /Widget /Rect [0 0 1 1] >>",
				"<< /Parent 4 0 R /Subtype /Widget /Rect [1 1 2 2] >>",
			},
			want: []string{"sig1"},
		},
		"a parent field with its own /V is the signed field": {
			fields:  "[4 0 R]",
			objects: []string{"<< /T (form) /FT /Sig /V 5 0 R /Kids [6 0 R] >>", sig, "<< /Parent 4 0 R /T (x) >>"},
			want:    []string{"form"},
		},
		"non-signature fields are skipped": {
			fields:  "[4 0 R 6 0 R]",
			objects: []string{"<< /T (text) /FT /Tx /V (x) >>", sig, "<< /T (sig1) /FT /Sig >>"},
			want:    []string{"sig1"},
		},
		"kids that loop back": {
			fields: "[4 0 R]",
			objects: []string{
				"<< /T (form) /Kids [6 0 R] >>", sig,
				"<< /Parent 4 0 R /T (inner) /Kids [4 0 R 7 0 R] >>",
				"<< /Parent 6 0 R /T (sig1) /FT /Sig >>",
			},
			want: []string{"sig1"},
		},
		"a field shared by parents of different types": {
			// Reached first under a text field, X inherits /Tx and is not a
			// signature; under the signature field it is, and is reported.
			fields: "[4 0 R 6 0 R]",
			objects: []string{
				"<< /T (a) /FT /Tx /V (x) /Kids [7 0 R] >>", sig,
				"<< /T (b) /FT /Sig /Kids [7 0 R] >>",
				"<< /T (x) /V 5 0 R >>",
			},
			want: []string{"x"},
		},
		"a field referencing itself": {
			fields:  "[4 0 R]",
			objects: []string{"<< /T (self) /FT /Sig /Kids [4 0 R] >>"},
			want:    nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := names(rootWithFields(t, tc.fields, tc.objects...))
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("signature fields = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("the walk stops when fn returns false", func(t *testing.T) {
		root := rootWithFields(t, "[4 0 R 5 0 R]", "<< /T (a) /FT /Sig >>", "<< /T (b) /FT /Sig >>")
		var got []string
		SignatureFields(root, func(field pdf.Value) bool {
			got = append(got, field.Key("T").Text())
			return false
		})
		if strings.Join(got, ",") != "a" {
			t.Errorf("walk continued after fn returned false: %q", got)
		}
	})

	t.Run("nesting beyond MaxDepth is cut off", func(t *testing.T) {
		// A chain of MaxDepth+2 untitled nodes with the signature at the end.
		depth := MaxDepth + 2
		objects := make([]string, 0, depth+1)
		for i := 0; i < depth; i++ {
			objects = append(objects, fmt.Sprintf("<< /T (n%d) /Kids [%d 0 R] >>", i, 5+i))
		}
		objects = append(objects, "<< /T (deep) /FT /Sig >>")
		if got := names(rootWithFields(t, "[4 0 R]", objects...)); len(got) != 0 {
			t.Errorf("signature beyond MaxDepth was reported: %q", got)
		}
	})
}

// TestFields covers the general walk: every field is reported, a parent
// before its kids, with fully qualified names (the partial names joined with
// periods, an untitled node adding nothing), inherited /FT and /V, and the
// terminal flag; FieldsOf walks one subtree under a given prefix.
func TestFields(t *testing.T) {
	root := rootWithFields(t, "[4 0 R 7 0 R 9 0 R]",
		"<< /T (form) /FT /Tx /V (default) /Kids [5 0 R 6 0 R] >>",
		"<< /Parent 4 0 R /T (name) /V (Ada) >>",
		"<< /Parent 4 0 R /Kids [10 0 R] >>",
		"<< /T (sig1) /FT /Sig >>",
		"<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] >>",
		"<< /T <FEFF0063006800650063006B> /FT /Btn /V /Yes /Kids [8 0 R] >>",
		"<< /Parent 6 0 R /T (deep) /FT /Ch >>",
	)

	describe := func(f Field) string {
		s := f.Name + ":" + f.Type + "=" + f.Value.Text()
		if f.Terminal {
			s += "*"
		}
		return s
	}
	var got []string
	Fields(root, func(f Field) bool {
		got = append(got, describe(f))
		return true
	})
	want := "form:Tx=default form.name:Tx=Ada* form:Tx=default form.deep:Ch=default* sig1:Sig=* check:Btn=*"
	if strings.Join(got, " ") != want {
		t.Errorf("Fields = %q, want %q", strings.Join(got, " "), want)
	}

	got = nil
	FieldsOf(root.Key("AcroForm").Key("Fields").Index(0), "doc", func(f Field) bool {
		got = append(got, describe(f))
		return true
	})
	want = "doc.form:Tx=default doc.form.name:Tx=Ada* doc.form:Tx=default doc.form.deep:Ch=default*"
	if strings.Join(got, " ") != want {
		t.Errorf("FieldsOf = %q, want %q", strings.Join(got, " "), want)
	}
}
