package acroform

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

// rootWithFields builds a document whose AcroForm /Fields array is fieldsArray
// (object 4 being the first extra object) and returns its catalog. Object 5 is
// a bare signature dictionary the fields can point at.
func rootWithFields(t *testing.T, fieldsArray string, objects ...string) pdf.Value {
	t.Helper()

	all := append([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields " + fieldsArray + " /SigFlags 3 >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}, objects...)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(all))
	for i, obj := range all {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(all)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(all)+1, xref)

	rdr, err := pdf.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return rdr.Trailer().Key("Root")
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
