package verify

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

// certifiedForm is revision 1 of the fixtures: a one-page certified form
// with a text field (8) and the certification signature field (10), whose
// signature dictionary (9) the catalog /Perms references, an appearance
// stream (11) and an information dictionary (12).
var certifiedForm = []string{
	"<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> >>",
	"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
	"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R] >>",
	"<< /Length 16 >>\nstream\nBT /F1 12 Tf ET\nendstream",
	"<< /Font << /F1 6 0 R >> >>",
	"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	"<< /Fields [8 0 R 10 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >>",
	"<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /V (Ada) /Rect [0 0 10 10] /AP << /N 11 0 R >> >>",
	"<< /Type /Sig /Filter /Adobe.PPKLite /Contents <01> /ByteRange [0 0 0 0] /Reference [ << /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >> ] >>",
	"<< /Type /Annot /Subtype /Widget /FT /Sig /T (cert) /V 9 0 R /Rect [0 0 0 0] >>",
	"<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Length 0 >>\nstream\n\nendstream",
	"<< /Producer (fixture) >>",
}

// templatedForm is certifiedForm with a page template named in the catalog
// (object 13), so that a page may be instantiated from it.
var templatedForm = append(append([]string(nil), certifiedForm...),
	"<< /Type /Page /MediaBox [0 0 612 792] >>",
)

func init() {
	templatedForm[0] = "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> /Names << /Templates << /Names [(blank) 13 0 R] >> >> >>"
}

// indirectForm is certifiedForm with the page's /Annots (13), the form's
// /Fields (14) and the catalog's /DSS (15, holding 16) as indirect objects,
// which an update may rewrite in place.
var indirectForm = append(append([]string(nil), certifiedForm...),
	"[8 0 R 10 0 R]",
	"[8 0 R 10 0 R]",
	"<< /Certs [16 0 R] >>",
	"<< /Length 4 >>\nstream\nCERT\nendstream",
)

func init() {
	indirectForm[0] = "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> /DSS 15 0 R >>"
	indirectForm[2] = "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots 13 0 R >>"
	indirectForm[6] = "<< /Fields 14 0 R /SigFlags 3 /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >>"
}

// update is an object an incremental update defines.
type update struct {
	id   int
	body string
}

// buildUpdate returns a file holding revision 1 with the given objects,
// numbered from 1, followed by an incremental update defining the updates
// under a classic cross-reference section, and the end of revision 1. root
// is the object number the update's trailer names as /Root, or 0 for 1; a
// negative root names object 3, the page, as the trailer's /Info instead.
func buildUpdate(t *testing.T, objects []string, root int, updates ...update) ([]byte, int64) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int64, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = writeObj(&buf, i+1, obj)
	}
	xref := int64(buf.Len())
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets[1:] {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info 12 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	signedEnd := int64(buf.Len())

	info := 12
	if root < 0 {
		root, info = 1, 3
	}
	if root == 0 {
		root = 1
	}
	size := len(objects) + 1
	updateOffsets := make([]int64, len(updates))
	for i, u := range updates {
		updateOffsets[i] = writeObj(&buf, u.id, u.body)
		if u.id >= size {
			size = u.id + 1
		}
	}
	xref2 := int64(buf.Len())
	buf.WriteString("xref\n")
	for i, u := range updates {
		fmt.Fprintf(&buf, "%d 1\n%010d 00000 n \n", u.id, updateOffsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", size, root, info, xref, xref2)
	return buf.Bytes(), signedEnd
}

// checkUpdate runs checkPermittedChanges over a file whose signed revision
// ends at signedEnd, at the given permission level.
func checkUpdate(t *testing.T, fileBytes []byte, signedEnd int64, password string, level int) error {
	t.Helper()
	file := bytes.NewReader(fileBytes)
	size := int64(len(fileBytes))
	signed, err := pdf.NewReaderEncrypted(io.NewSectionReader(file, 0, signedEnd), signedEnd, passwordFunc(password))
	if err != nil {
		t.Fatalf("read signed revision: %v", err)
	}
	current, err := pdf.NewReaderEncrypted(file, size, passwordFunc(password))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	return checkPermittedChanges(signed, current, docMDPPermissions(level))
}

// TestCheckPermittedChanges covers ISO 32000-1 Table 254: what an
// incremental update after a certification signature may change at each
// permission level, with validation data and document timestamps permitted
// at every level.
func TestCheckPermittedChanges(t *testing.T) {
	const (
		approval  = "<< /Type /Sig /Filter /Adobe.PPKLite /Contents <02> /ByteRange [0 0 0 0] >>"
		timestamp = "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /Contents <03> /ByteRange [0 0 0 0] >>"
		rotated   = "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R] /Rotate 90 >>"
	)
	signing := func(value string) []update {
		return []update{
			{7, "<< /Fields [8 0 R 10 0 R 13 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >>"},
			{3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R 13 0 R] >>"},
			{13, "<< /Type /Annot /Subtype /Widget /FT /Sig /T (sig2) /V 14 0 R /Rect [0 0 0 0] >>"},
			{14, value},
		}
	}
	for _, tc := range []struct {
		name    string
		objects []string // revision 1, certifiedForm when nil
		root    int
		updates []update
		// permitted lists the levels at which the update passes; the other
		// levels have to report a violation containing violation.
		permitted []int
		violation string
	}{
		{"an unreferenced object", nil, 0, []update{{13, "<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] >>"}}, []int{1, 2, 3}, ""},
		{"the page's content stream", nil, 0, []update{{4, "<< /Length 30 >>\nstream\nBT /F1 12 Tf (HACKED) Tj ET\nendstream"}}, nil, "rewrites object 4"},
		{"the page object", nil, 0, []update{{3, rotated}}, nil, "/Rotate of page object 3"},
		{"the page's resources", nil, 0, []update{{5, "<< /Font << /F1 6 0 R /F2 6 0 R >> >>"}}, nil, "rewrites object 5"},
		{"a font the page uses", nil, 0, []update{{6, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"}}, nil, "rewrites object 6"},
		{"a content stream freed", nil, 0, []update{{4, "null"}}, nil, "removes object 4"},
		{"an identical rewrite", nil, 0, []update{{3, certifiedForm[2]}, {4, certifiedForm[3]}}, []int{1, 2, 3}, ""},
		{"a form fill", nil, 0, []update{
			{8, "<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /V (Bob) /Rect [0 0 10 10] /AP << /N 13 0 R >> >>"},
			{13, "<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Length 0 >>\nstream\n\nendstream"},
		}, []int{2, 3}, "of field 8"},
		{"a field renamed", nil, 0, []update{{8, "<< /Type /Annot /Subtype /Widget /FT /Tx /T (other) /V (Ada) /Rect [0 0 10 10] /AP << /N 11 0 R >> >>"}}, nil, "/T of field 8"},
		{"a field freed", nil, 0, []update{{8, "null"}}, nil, "removes object 8"},
		{"a field removed from the form", nil, 0, []update{{7, "<< /Fields [10 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >>"}}, nil, "removes a field"},
		{"a text field added to the form", nil, 0, []update{
			{7, "<< /Fields [8 0 R 10 0 R 13 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >>"},
			{13, "<< /Type /Annot /Subtype /Widget /FT /Tx /T (extra) /Rect [0 0 10 10] >>"},
		}, nil, "not a signature field"},
		{"an approval signature", nil, 0, signing(approval), []int{2, 3}, "adds a signature field"},
		{"a document timestamp", nil, 0, signing(timestamp), []int{1, 2, 3}, ""},
		{"a widget attached to the signed field", nil, 0, []update{
			{3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R 13 0 R] >>"},
			{13, "<< /Type /Annot /Subtype /Widget /Parent 10 0 R /Rect [0 0 612 792] /AP << /N 11 0 R >> >>"},
		}, []int{3}, "adds an annotation to page object 3"},
		{"the certification signature re-signed", nil, 0, []update{{10, "<< /Type /Annot /Subtype /Widget /FT /Sig /T (cert) /V 14 0 R /Rect [0 0 0 0] >>"}, {14, approval}}, nil, "changes the signature of field 10"},
		{"the signature dictionary rewritten", nil, 0, []update{{9, approval}}, nil, "rewrites the signature dictionary 9"},
		{"an annotation added", nil, 0, []update{
			{3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R 13 0 R] >>"},
			{13, "<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] >>"},
		}, []int{3}, "adds an annotation to page object 3"},
		{"an annotation removed", nil, 0, []update{{3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [10 0 R] >>"}}, []int{3}, "removes an annotation from page object 3"},
		{"validation data", nil, 13, []update{
			{13, "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> /DSS 14 0 R >>"},
			{14, "<< /Certs [15 0 R] >>"},
			{15, "<< /Length 4 >>\nstream\nCERT\nendstream"},
		}, []int{1, 2, 3}, ""},
		{"validation data grown", nil, 13, []update{
			{13, "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> /DSS 14 0 R >>"},
			{14, "<< /Certs [15 0 R] >>"},
			{15, "<< /Length 4 >>\nstream\nCERT\nendstream"},
		}, []int{1, 2, 3}, ""},
		{"the information dictionary", nil, 0, []update{{12, "<< /Producer (fixture) /ModDate (D:20260923000000Z) >>"}}, []int{1, 2, 3}, ""},
		{"a replaced catalog with another page tree", nil, 13, []update{{13, "<< /Type /Catalog /Pages 14 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> >>"}, {14, "<< /Type /Pages /Kids [] /Count 0 >>"}}, nil, "catalog entry /Pages"},
		{"the catalog /Perms dropped", nil, 13, []update{{13, "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R >>"}}, nil, "catalog entry /Perms"},
		{"a page appended from a template", templatedForm, 0, []update{
			{2, "<< /Type /Pages /Kids [3 0 R 14 0 R] /Count 2 >>"},
			{14, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"},
		}, []int{2, 3}, "page tree node 2"},
		{"a page appended without a template", nil, 0, []update{
			{2, "<< /Type /Pages /Kids [3 0 R 13 0 R] /Count 2 >>"},
			{13, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"},
		}, nil, "page tree node 2"},
		{"a page removed", nil, 0, []update{{2, "<< /Type /Pages /Kids [] /Count 0 >>"}}, nil, "page tree node 2"},
		{"the page shielded through the trailer /Info", nil, -1, []update{{3, rotated}}, nil, "/Rotate of page object 3"},
		{"the page shielded through the catalog /DSS", nil, 13, []update{
			{13, "<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Perms << /DocMDP 9 0 R >> /DSS << /Certs [3 0 R] >> >>"},
			{3, rotated},
		}, nil, "/Rotate of page object 3"},
		{"validation data grown in place", indirectForm, 0, []update{
			{15, "<< /Certs [16 0 R 17 0 R] >>"},
			{17, "<< /Length 4 >>\nstream\nCERT\nendstream"},
		}, []int{1, 2, 3}, ""},
		{"an annotation added to an indirect /Annots", indirectForm, 0, []update{
			{13, "[8 0 R 10 0 R 17 0 R]"},
			{17, "<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] >>"},
		}, []int{3}, "adds an annotation to page object 3"},
		{"a signature field added to an indirect /Fields and /Annots", indirectForm, 0, []update{
			{13, "[8 0 R 10 0 R 17 0 R]"},
			{14, "[8 0 R 10 0 R 17 0 R]"},
			{17, "<< /Type /Annot /Subtype /Widget /FT /Sig /T (sig2) /V 18 0 R /Rect [0 0 0 0] >>"},
			{18, approval},
		}, []int{2, 3}, "adds a signature field"},
		{"a field removed from an indirect /Fields", indirectForm, 0, []update{{14, "[10 0 R]"}}, nil, "removes a field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := tc.objects
			if objects == nil {
				objects = certifiedForm
			}
			fileBytes, signedEnd := buildUpdate(t, objects, tc.root, tc.updates...)
			for level := 1; level <= 3; level++ {
				err := checkUpdate(t, fileBytes, signedEnd, "", level)
				useXrefTables = false
				exhaustive := checkUpdate(t, fileBytes, signedEnd, "", level)
				useXrefTables = true
				if (err == nil) != (exhaustive == nil) || (err != nil && err.Error() != exhaustive.Error()) {
					t.Errorf("P=%d: comparing every object gives %v, the cross-reference entries %v", level, exhaustive, err)
				}
				permitted := false
				for _, l := range tc.permitted {
					permitted = permitted || l == level
				}
				switch {
				case permitted && err != nil:
					t.Errorf("P=%d: got %v, want the update permitted", level, err)
				case !permitted && err == nil:
					t.Errorf("P=%d: got no error, want a violation containing %q", level, tc.violation)
				case !permitted && (!strings.Contains(err.Error(), tc.violation) || !strings.Contains(err.Error(), fmt.Sprintf("P=%d", level))):
					t.Errorf("P=%d: got %v, want a violation containing %q", level, err, tc.violation)
				}
			}
		})
	}
}

// TestCheckPermittedChangesRepointed covers an update whose cross-reference
// section points the text field at the bytes of another object without
// writing an object of its own: the field then reads as nothing, and the
// section names it as changed.
func TestCheckPermittedChangesRepointed(t *testing.T) {
	fileBytes, signedEnd := buildUpdate(t, certifiedForm, 0)
	fileBytes = fileBytes[:signedEnd]
	var offsets []int64
	for _, m := range regexp.MustCompile(`(?m)^(\d+) 0 obj`).FindAllIndex(fileBytes, -1) {
		offsets = append(offsets, int64(m[0]))
	}
	prev := bytes.LastIndex(fileBytes, []byte("startxref\n")) + len("startxref\n")
	var prevOffset int64
	if _, err := fmt.Sscanf(string(fileBytes[prev:]), "%d", &prevOffset); err != nil {
		t.Fatalf("startxref of the signed revision: %v", err)
	}

	var buf bytes.Buffer
	buf.Write(fileBytes)
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n8 1\n%010d 00000 n \n", offsets[5]) // the font's bytes
	fmt.Fprintf(&buf, "trailer\n<< /Size 13 /Root 1 0 R /Info 12 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prevOffset, xref)
	fileBytes = buf.Bytes()

	err := checkUpdate(t, fileBytes, signedEnd, "", 3)
	if err == nil || !strings.Contains(err.Error(), "removes object 8") {
		t.Errorf("got %v, want the re-pointed field reported as removed", err)
	}
}

// TestCheckPermittedChangesXrefStreamRepointed covers an update whose
// cross-reference stream points the text field at the bytes of another
// object and lists neither the field's object nor itself among the objects
// the document resolves: the stream's /Index still names the field as
// changed.
func TestCheckPermittedChangesXrefStreamRepointed(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	rows := []xrefStreamRow{{0, 0, 65535}}
	var offsets []int64
	for i, obj := range certifiedForm {
		offsets = append(offsets, writeObj(&buf, i+1, obj))
		rows = append(rows, xrefStreamRow{1, uint32(offsets[i]), 0})
	}
	xref1 := buf.Len()
	rows = append(rows, xrefStreamRow{1, uint32(xref1), 0})
	writeXrefStream(&buf, 13, "0 14", "/Size 14 /Root 1 0 R /Info 12 0 R", rows...)
	signedEnd := int64(buf.Len())

	// The font's bytes for object 8; the stream (object 14) is not listed.
	writeXrefStream(&buf, 14, "8 1", fmt.Sprintf("/Size 15 /Root 1 0 R /Info 12 0 R /Prev %d", xref1),
		xrefStreamRow{1, uint32(offsets[5]), 0})
	fileBytes := buf.Bytes()

	err := checkUpdate(t, fileBytes, signedEnd, "", 3)
	if err == nil || !strings.Contains(err.Error(), "removes object 8") {
		t.Errorf("got %v, want the re-pointed field reported as removed", err)
	}
}

// TestCheckPermittedChangesObscuredHeaders covers an update whose object
// headers carry a comment between the object number and the keyword, which
// the reader skips: the page rewrite is found through the cross-reference
// entries the reader parsed, not through the text of the update.
func TestCheckPermittedChangesObscuredHeaders(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	rows := []xrefStreamRow{{0, 0, 65535}}
	for i, obj := range certifiedForm {
		rows = append(rows, xrefStreamRow{1, uint32(writeObj(&buf, i+1, obj)), 0})
	}
	xref1 := buf.Len()
	rows = append(rows, xrefStreamRow{1, uint32(xref1), 0})
	writeXrefStream(&buf, 13, "0 14", "/Size 14 /Root 1 0 R /Info 12 0 R", rows...)
	signedEnd := int64(buf.Len())

	pageOffset := buf.Len()
	buf.WriteString("3%evade\n0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R] /Rotate 90 >>\nendobj\n")
	xref2 := buf.Len()
	var data bytes.Buffer
	for _, r := range []xrefStreamRow{{1, uint32(pageOffset), 0}, {1, uint32(xref2), 0}} {
		data.WriteByte(r.kind)
		_ = binary.Write(&data, binary.BigEndian, r.field2)
		_ = binary.Write(&data, binary.BigEndian, r.field3)
	}
	fmt.Fprintf(&buf, "14%%evade\n0 obj\n<< /Type /XRef /W [1 4 2] /Index [3 1 14 1] /Size 15 /Root 1 0 R /Info 12 0 R /Prev %d /Length %d >>\nstream\n", xref1, data.Len())
	buf.Write(data.Bytes())
	fmt.Fprintf(&buf, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xref2)
	fileBytes := buf.Bytes()

	current, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if got := current.Trailer().Key("Root").Key("Pages").Key("Kids").Index(0).Key("Rotate").Int64(); got != 90 {
		t.Fatalf("the obscured update did not take effect: /Rotate = %d", got)
	}
	err = checkUpdate(t, fileBytes, signedEnd, "", 3)
	if err == nil || !strings.Contains(err.Error(), "/Rotate of page object 3") {
		t.Errorf("got %v, want the page rewrite behind the obscured headers reported", err)
	}
}

// TestXrefEntries checks that the reader's cross-reference entries can be
// read, so that changed objects are found through them rather than by
// comparing every object.
func TestXrefEntries(t *testing.T) {
	fileBytes, signedEnd := buildUpdate(t, certifiedForm, 0, update{3, certifiedForm[2] + " "}, update{13, "<< /Type /Annot >>"})
	file := bytes.NewReader(fileBytes)
	signed, err := pdf.NewReader(io.NewSectionReader(file, 0, signedEnd), signedEnd)
	if err != nil {
		t.Fatal(err)
	}
	current, err := pdf.NewReader(file, int64(len(fileBytes)))
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := xrefEntries(current)
	if !ok || len(entries) != 14 || entries[3].offset < signedEnd || entries[2].offset >= signedEnd {
		t.Fatalf("xrefEntries = %v, %v; want 14 entries with object 3 in the update and object 2 in the signed revision", entries, ok)
	}
	if got := changedObjects(signed, current); len(got) != 2 || got[0] != 3 || got[1] != 13 {
		t.Errorf("changedObjects = %v, want [3 13]", got)
	}
}

// xrefStreamRow is a row of a cross-reference stream with /W [1 4 2].
type xrefStreamRow struct {
	kind   byte
	field2 uint32
	field3 uint16
}

// writeXrefStream writes a cross-reference stream object holding the rows
// for the objects index names, with the given trailer entries, followed by
// the startxref line and %%EOF.
func writeXrefStream(buf *bytes.Buffer, id int, index string, trailer string, rows ...xrefStreamRow) {
	var data bytes.Buffer
	for _, r := range rows {
		data.WriteByte(r.kind)
		_ = binary.Write(&data, binary.BigEndian, r.field2)
		_ = binary.Write(&data, binary.BigEndian, r.field3)
	}
	offset := buf.Len()
	fmt.Fprintf(buf, "%d 0 obj\n<< /Type /XRef /W [1 4 2] /Index [%s] %s /Length %d >>\nstream\n", id, index, trailer, data.Len())
	buf.Write(data.Bytes())
	fmt.Fprintf(buf, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", offset)
}

// TestCheckPermittedChangesObjectStream covers an update that rewrites the
// page inside an object stream, under cross-reference streams: the object
// has no header of its own in the update, and is found through the stream.
func TestCheckPermittedChangesObjectStream(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	rows := []xrefStreamRow{{0, 0, 65535}}
	for i, obj := range certifiedForm {
		rows = append(rows, xrefStreamRow{1, uint32(writeObj(&buf, i+1, obj)), 0})
	}
	xref1 := buf.Len()
	rows = append(rows, xrefStreamRow{1, uint32(xref1), 0})
	writeXrefStream(&buf, 13, "0 14", "/Size 14 /Root 1 0 R /Info 12 0 R", rows...)
	signedEnd := int64(buf.Len())

	page := "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources 5 0 R /MediaBox [0 0 612 792] /Annots [8 0 R 10 0 R] /Rotate 90 >>"
	header := "3 0 "
	objStm := fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n%s%s\nendstream", len(header), len(header)+len(page), header, page)
	objStmOffset := writeObj(&buf, 14, objStm)
	xref2 := buf.Len()
	writeXrefStream(&buf, 15, "3 1 14 2", fmt.Sprintf("/Size 16 /Root 1 0 R /Info 12 0 R /Prev %d", xref1),
		xrefStreamRow{2, 14, 0}, xrefStreamRow{1, uint32(objStmOffset), 0}, xrefStreamRow{1, uint32(xref2), 0})

	fileBytes := buf.Bytes()
	current, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if got := current.Trailer().Key("Root").Key("Pages").Key("Kids").Index(0).Key("Rotate").Int64(); got != 90 {
		t.Fatalf("the object stream did not take effect: /Rotate = %d", got)
	}
	err = checkUpdate(t, fileBytes, signedEnd, "", 3)
	if err == nil || !strings.Contains(err.Error(), "/Rotate of page object 3") {
		t.Errorf("got %v, want the page rewrite inside the object stream reported", err)
	}
}

// TestCheckPermittedChangesEncrypted checks that the changes of an encrypted
// document are checked when the password is known, rather than skipped
// because the document cannot be opened.
func TestCheckPermittedChangesEncrypted(t *testing.T) {
	const password = "pdfsign"
	original, err := os.ReadFile("../testfiles/encrypted/aes256_r6.pdf")
	if err != nil {
		t.Fatal(err)
	}
	rdr, err := pdf.NewReaderEncrypted(bytes.NewReader(original), int64(len(original)), passwordFunc(password))
	if err != nil {
		t.Fatal(err)
	}
	trailer := rdr.Trailer()
	pageID := rdr.Page(1).V.GetPtr().GetID()
	ids := trailer.Key("ID")

	// Append an update that rewrites the page object.
	var buf bytes.Buffer
	buf.Write(original)
	signedEnd := int64(buf.Len())
	offset := writeObj(&buf, int(pageID), "<< /Type /Page /Rotate 90 >>")
	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n%d 1\n%010d 00000 n \n", pageID, offset)
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R /Encrypt %d 0 R /ID [<%x><%x>] /Prev %d >>\n",
		trailer.Key("Size").Int64(), trailer.Key("Root").GetPtr().GetID(), trailer.Key("Encrypt").GetPtr().GetID(),
		ids.Index(0).RawString(), ids.Index(1).RawString(), rdr.XrefInformation.StartPos)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset)
	fileBytes := buf.Bytes()

	err = checkUpdate(t, fileBytes, signedEnd, password, 3)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("page object %d", pageID)) {
		t.Errorf("got %v, want the page rewrite of the encrypted document reported", err)
	}
}
