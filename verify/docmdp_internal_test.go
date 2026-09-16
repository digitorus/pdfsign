package verify

import (
	"bytes"
	"fmt"
	"testing"
)

// writeObj writes a classic PDF object definition to buf and returns its byte offset.
func writeObj(buf *bytes.Buffer, id int, body string) int64 {
	offset := int64(buf.Len())
	fmt.Fprintf(buf, "%d 0 obj\n%s\nendobj\n", id, body)
	return offset
}

// buildMinimalPDFWithUpdate constructs a minimal one-page classic-xref PDF
// (revision 1: objects 1-6, a Catalog/Pages/Page/Contents/Resources/Font)
// followed by an incremental update (revision 2) that writes rewriteBody
// under object number rewriteID - either rewriting an existing object from
// revision 1, or adding a new one. It returns the full file bytes and the
// byte offset marking the end of revision 1 (i.e. what a signature's
// ByteRange would cover if it signed exactly revision 1).
func buildMinimalPDFWithUpdate(t *testing.T, rewriteID int, rewriteBody string) (fileBytes []byte, signedEnd int64) {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")

	offsets := make(map[int]int64)
	offsets[1] = writeObj(&buf, 1, "<< /Type /Catalog /Pages 2 0 R >>")
	offsets[2] = writeObj(&buf, 2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	offsets[3] = writeObj(&buf, 3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] >>")
	offsets[4] = writeObj(&buf, 4, "<< /Length 16 >>\nstream\nBT /F1 12 Tf ET\nendstream")
	offsets[5] = writeObj(&buf, 5, "<< /Font << /F1 6 0 R >> >>")
	offsets[6] = writeObj(&buf, 6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefOffset := int64(buf.Len())
	buf.WriteString("xref\n0 7\n0000000000 65535 f \n")
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	buf.WriteString("trailer\n<< /Size 7 /Root 1 0 R >>\n")
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	signedEnd = int64(buf.Len())

	// Revision 2: an incremental update writing a single object.
	newOffset := writeObj(&buf, rewriteID, rewriteBody)
	xrefOffset2 := int64(buf.Len())
	fmt.Fprintf(&buf, "xref\n%d 1\n%010d 00000 n \n", rewriteID, newOffset)
	fmt.Fprintf(&buf, "trailer\n<< /Size 7 /Root 1 0 R /Prev %d >>\n", xrefOffset)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset2)

	return buf.Bytes(), signedEnd
}

func TestCheckIncrementalUpdateScope(t *testing.T) {
	t.Run("update adding a new, unrelated object is allowed", func(t *testing.T) {
		// Object 7 doesn't exist in revision 1 and isn't part of the page
		// tree - e.g. a new AcroForm field or annotation added by a
		// legitimate P=2/P=3 update.
		fileBytes, signedEnd := buildMinimalPDFWithUpdate(t, 7, "<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] >>")
		r := bytes.NewReader(fileBytes)
		if err := checkIncrementalUpdateScope(r, int64(len(fileBytes)), signedEnd); err != nil {
			t.Errorf("expected no error for an update that only adds a new object, got: %v", err)
		}
	})

	t.Run("update rewriting the page's content stream is rejected", func(t *testing.T) {
		fileBytes, signedEnd := buildMinimalPDFWithUpdate(t, 4,
			"<< /Length 30 >>\nstream\nBT /F1 12 Tf (HACKED) Tj ET\nendstream")
		r := bytes.NewReader(fileBytes)
		err := checkIncrementalUpdateScope(r, int64(len(fileBytes)), signedEnd)
		if err == nil {
			t.Fatal("expected an error for an update that rewrites the page's content stream, got nil")
		}
		t.Logf("got expected error: %v", err)
	})

	t.Run("update rewriting the page object itself is rejected", func(t *testing.T) {
		fileBytes, signedEnd := buildMinimalPDFWithUpdate(t, 3,
			"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Rotate 90 >>")
		r := bytes.NewReader(fileBytes)
		if err := checkIncrementalUpdateScope(r, int64(len(fileBytes)), signedEnd); err == nil {
			t.Fatal("expected an error for an update that rewrites the page object itself, got nil")
		}
	})

	t.Run("update rewriting the Resources dict is rejected", func(t *testing.T) {
		fileBytes, signedEnd := buildMinimalPDFWithUpdate(t, 5, "<< /Font << /F1 6 0 R /F2 6 0 R >> >>")
		r := bytes.NewReader(fileBytes)
		if err := checkIncrementalUpdateScope(r, int64(len(fileBytes)), signedEnd); err == nil {
			t.Fatal("expected an error for an update that rewrites the page's Resources dict, got nil")
		}
	})

	t.Run("update rewriting a font referenced by Resources is rejected", func(t *testing.T) {
		fileBytes, signedEnd := buildMinimalPDFWithUpdate(t, 6,
			"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
		r := bytes.NewReader(fileBytes)
		if err := checkIncrementalUpdateScope(r, int64(len(fileBytes)), signedEnd); err == nil {
			t.Fatal("expected an error for an update that rewrites a font referenced by the page's Resources, got nil")
		}
	})
}
