package verify_test

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"

	"github.com/digitorus/pdf"
)

var lastStartxref = regexp.MustCompile(`startxref\r?\n(\d+)\r?\n%%EOF\r?\n?$`)

// appendUpdate returns the file with an incremental update that redefines
// one object, chained to the file's last cross-reference section through a
// classic cross-reference section. trailer is the file's trailer, for its
// /Size and /Root.
func appendUpdate(t *testing.T, original []byte, trailer pdf.Value, objectNumber uint32, body string) []byte {
	t.Helper()
	prev := lastStartxref.FindSubmatch(original)
	if prev == nil {
		t.Fatal("startxref of the signed file not found")
	}
	rootPtr := trailer.Key("Root").GetPtr()

	var updated bytes.Buffer
	updated.Write(original)
	if !bytes.HasSuffix(original, []byte("\n")) {
		updated.WriteString("\n")
	}
	offset := updated.Len()
	fmt.Fprintf(&updated, "%d 0 obj\n%s\nendobj\n", objectNumber, body)
	xref := updated.Len()
	fmt.Fprintf(&updated, "xref\n0 1\n0000000000 65535 f \n%d 1\n%010d 00000 n \n", objectNumber, offset)
	fmt.Fprintf(&updated, "trailer\n<< /Size %d /Root %d %d R /Prev %s >>\nstartxref\n%d\n%%%%EOF\n",
		trailer.Key("Size").Int64(), rootPtr.GetID(), rootPtr.GetGen(), string(prev[1]), xref)
	return updated.Bytes()
}

// objectText returns the text of the latest definition of an object in the
// file, between its "obj" and "endobj" keywords.
func objectText(t *testing.T, file []byte, objectNumber uint32) string {
	t.Helper()
	definitions := regexp.MustCompile(fmt.Sprintf(`(?s)\n%d 0 obj\r?\n(.*?)\r?\nendobj`, objectNumber)).FindAllSubmatch(file, -1)
	if definitions == nil {
		t.Fatalf("object %d not found in the file", objectNumber)
	}
	return string(definitions[len(definitions)-1][1])
}
