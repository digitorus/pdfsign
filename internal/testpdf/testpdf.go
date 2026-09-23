// Package testpdf builds small PDF files for tests.
package testpdf

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/digitorus/pdf"
)

// Bytes returns a PDF with a classic cross-reference table holding the given
// objects, numbered from 1; object 1 is the document catalog.
func Bytes(objects ...string) []byte {
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
	return buf.Bytes()
}

// Reader returns a reader over Bytes(objects...).
func Reader(t testing.TB, objects ...string) *pdf.Reader {
	t.Helper()
	b := Bytes(objects...)
	rdr, err := pdf.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("read test PDF: %v", err)
	}
	return rdr
}
