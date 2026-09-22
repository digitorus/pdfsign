package sign

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/mattetti/filebuffer"
)

// fakeEncrypter makes the encryption visible in test output: it prefixes the
// data with the object number and reverses it.
type fakeEncrypter struct{}

func (fakeEncrypter) Trailer() pdf.Value { return pdf.Value{} }

func (fakeEncrypter) EncryptsMetadata() bool { return true }

func (fakeEncrypter) Encrypt(ptr pdf.Ptr, data []byte) ([]byte, error) {
	out := []byte(fmt.Sprintf("%d:", ptr.GetID()))
	for i := len(data) - 1; i >= 0; i-- {
		out = append(out, data[i])
	}
	return out, nil
}

func fakeHex(id uint32, plain string) string {
	enc, _ := fakeEncrypter{}.Encrypt(pdf.NewPtr(id, 0), []byte(plain))
	return "<" + strings.ToUpper(hex.EncodeToString(enc)) + ">"
}

func TestEncryptObject(t *testing.T) {
	const id = 7
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "literal and hex strings",
			in:   "<< /T (Signature 1) /Name <FEFF0628> /Empty () >>",
			want: "<< /T " + fakeHex(id, "Signature 1") + " /Name " + fakeHex(id, "\xFE\xFF\x06\x28") + " /Empty " + fakeHex(id, "") + " >>",
		},
		{
			name: "escapes and balanced parentheses",
			in:   `<< /A (a\)b\\c\n\101\0501) /B (x(y)z) /C (line\` + "\n" + `cont) >>`,
			want: "<< /A " + fakeHex(id, "a)b\\c\nA(1") + " /B " + fakeHex(id, "x(y)z") + " /C " + fakeHex(id, "linecont") + " >>",
		},
		{
			name: "control escapes and end-of-line markers",
			in:   `<< /A (\r\t\b\f) /B (a\` + "\r\n" + `b) /C (a` + "\r\n" + `b` + "\r" + `c) >>`,
			want: "<< /A " + fakeHex(id, "\r\t\b\f") + " /B " + fakeHex(id, "ab") + " /C " + fakeHex(id, "a\nb\nc") + " >>",
		},
		{
			name: "comments are kept and not parsed",
			in:   "<< /A (x) % not a (string\r/B (y) >>",
			want: "<< /A " + fakeHex(id, "x") + " % not a (string\r/B " + fakeHex(id, "y") + " >>",
		},
		{
			name: "odd hex digits and whitespace",
			in:   "[<41 4>]",
			want: "[" + fakeHex(id, "A@") + "]",
		},
		{
			name: "names, numbers, references and nested containers",
			in:   "<< /Type /Annot /Rect [1 2.5 3 4] /P 3 0 R /MK << /CA (x) >> /Contents (note) >>",
			want: "<< /Type /Annot /Rect [1 2.5 3 4] /P 3 0 R /MK << /CA " + fakeHex(id, "x") + " >> /Contents " + fakeHex(id, "note") + " >>",
		},
		{
			name: "signature dictionary keeps Contents and ByteRange placeholders",
			in:   "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n " + signatureByteRangePlaceholder + " /Contents<0000>\n /Name (John)\n /Reference [ << /Contents (ref) >> ]\n>>",
			want: "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n " + signatureByteRangePlaceholder + " /Contents<0000>\n /Name " + fakeHex(id, "John") + "\n /Reference [ " + "<< /Contents " + fakeHex(id, "ref") + " >> ]\n>>",
		},
		{
			name: "document timestamp keeps Contents",
			in:   "<< /Type /DocTimeStamp /Contents<00> >>",
			want: "<< /Type /DocTimeStamp /Contents<00> >>",
		},
		{
			name: "stream data is encrypted and Length updated",
			in:   "<<\n  /Type /XObject\n  /Length 5\n  /Length1 99\n>>\nstream\nhello\nendstream",
			want: "<<\n  /Type /XObject\n  /Length 7\n  /Length1 99\n>>\nstream\n7:olleh\nendstream",
		},
		{
			name: "stream data containing endstream and parentheses",
			in:   "<< /Length 12 >>stream\r\n(endstream)\n\nendstream",
			want: "<< /Length 14 >>stream\r\n7:\n)maertsdne(\nendstream",
		},
		{
			name: "empty stream",
			in:   "<< /Length 0 >>\nstream\n\nendstream",
			want: "<< /Length 2 >>\nstream\n7:\nendstream",
		},
		{
			name: "stream data ending right before endstream",
			in:   "<< /Length 3 >>\nstream\nabcendstream",
			want: "<< /Length 5 >>\nstream\n7:cbaendstream",
		},
		{
			name: "xref stream is not encrypted",
			in:   "<< /Type /XRef /ID [<01><02>] /Length 3 >>\nstream\nabc\nendstream",
			want: "<< /Type /XRef /ID [<01><02>] /Length 3 >>\nstream\nabc\nendstream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptObject(fakeEncrypter{}, id, []byte(tt.in))
			if err != nil {
				t.Fatalf("encryptObject: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("encryptObject:\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestEncryptObjectErrors(t *testing.T) {
	for _, in := range []string{
		"<< /Length 4 0 R >>\nstream\nabcd\nendstream",               // indirect Length
		"<< /Length 10 >>\nstream\nabc\nendstream",                   // Length beyond the data
		"<< /Length x >>\nstream\nabcd\nendstream",                   // Length not a number
		"<< /Type /XObject >>\nstream\nabcd\nendstream",              // Length missing
		"<< /Length 4 >>\nstreamabcd\nendstream",                     // no end-of-line after stream
		"<< /Length 9223372036854775807 >>\nstream\nabc\nendstream",  // offset+Length overflows
		"<< /Length 99999999999999999999 >>\nstream\nabc\nendstream", // Length out of range
		"<< /Length -1 >>\nstream\nabc\nendstream",
		"<< /Length 5 >>\nstream\nabc\nendstream", // Length reaches into endstream
		"<< /Length 3 >>\nstream\nabc",            // no endstream
		"<< /Length 0 >>\nstream\n",
		"<< /T (unterminated >>",
		"<< /T (escape at the end\\",
		"<< /T <4142 >>", // stray ">" after the string
		"<< /T <4142",
		"<< /T <4G> >>",
		">>",
		"<< /A [1 2 >>",
		"]",
		"<< /A << /B 1 >>",
	} {
		if _, err := encryptObject(fakeEncrypter{}, 1, []byte(in)); err == nil {
			t.Errorf("encryptObject(%q): want error, got nil", in)
		}
	}
}

type failingEncrypter struct{ fakeEncrypter }

func (failingEncrypter) Encrypt(pdf.Ptr, []byte) ([]byte, error) {
	return nil, errors.New("encryption failed")
}

func TestEncryptObjectEncrypterError(t *testing.T) {
	for _, in := range []string{
		"<< /T (x) >>",
		"<< /Length 1 >>\nstream\nx\nendstream",
	} {
		if _, err := encryptObject(failingEncrypter{}, 1, []byte(in)); err == nil || !strings.Contains(err.Error(), "encryption failed") {
			t.Errorf("encryptObject(%q) error = %v, want the encrypter error", in, err)
		}
	}
}

func TestWriteObjectUnencryptedUnchanged(t *testing.T) {
	obj := []byte("<< /T (Signature 1) >>")
	got, err := encryptObject(nil, 1, obj)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, obj) {
		t.Errorf("got %q, want %q", got, obj)
	}
}

func openEncryptedReader(t *testing.T, path string) *pdf.Reader {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return openEncryptedBytes(t, data)
}

func openEncryptedBytes(t *testing.T, data []byte) *pdf.Reader {
	t.Helper()
	offered := false
	rdr, err := pdf.NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), func() string {
		if offered {
			return ""
		}
		offered = true
		return "pdfsign"
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return rdr
}

// appendEncrypted adds objects, passed through encryptObject, to the
// encrypted document data as an incremental update with a cross-reference
// table, and returns the objects as written and the updated document.
func appendEncrypted(t *testing.T, data []byte, objects map[uint32]string) (map[uint32][]byte, []byte) {
	t.Helper()
	rdr := openEncryptedBytes(t, data)
	trailer := rdr.Trailer()

	out := bytes.NewBuffer(bytes.Clone(data))
	if !bytes.HasSuffix(data, []byte("\n")) {
		out.WriteByte('\n')
	}
	ids := slices.Sorted(maps.Keys(objects))
	written := make(map[uint32][]byte)
	offsets := make(map[uint32]int)
	for _, id := range ids {
		obj, err := encryptObject(rdr, id, []byte(objects[id]))
		if err != nil {
			t.Fatalf("encryptObject(%d): %v", id, err)
		}
		written[id] = obj
		offsets[id] = out.Len()
		fmt.Fprintf(out, "%d 0 obj\n%s\nendobj\n", id, obj)
	}

	xref := out.Len()
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, id := range ids {
		fmt.Fprintf(out, "%d 1\n%010d 00000 n \n", id, offsets[id])
	}
	size := max(trailer.Key("Size").Int64(), int64(ids[len(ids)-1])+1)
	id := trailer.Key("ID")
	fmt.Fprintf(out, "trailer << /Size %d /Root %d 0 R /Encrypt %d 0 R /ID [<%x><%x>] /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		size, trailer.Key("Root").GetPtr().GetID(), trailer.Key("Encrypt").GetPtr().GetID(),
		id.Index(0).RawString(), id.Index(1).RawString(), rdr.XrefInformation.StartPos, xref)
	return written, out.Bytes()
}

// readBackStream returns the decoded data of stream object id.
func readBackStream(t *testing.T, rdr *pdf.Reader, id uint32) string {
	t.Helper()
	v, err := rdr.GetObject(id)
	if err != nil {
		t.Fatalf("GetObject(%d): %v", id, err)
	}
	rc := v.Reader()
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading stream %d: %v", id, err)
	}
	return string(data)
}

// streamObject returns a stream object with data and extra dictionary entries.
func streamObject(entries, data string) string {
	return fmt.Sprintf("<< %s /Length %d >>\nstream\n%s\nendstream", entries, len(data), data)
}

// ISO 32000-2, 7.6.5 and 7.6.7: a stream whose first filter is /Crypt is
// encrypted with the method of the crypt filter it names. aes128_r4_crypt_filters.pdf
// is aes128_r4.pdf with an incremental update that adds crypt filters with the
// default method AESV2 (SameMethod), without a method (NoMethod) and with RC4
// (OtherMethod) to the encryption dictionary.
func TestEncryptObjectCryptFilters(t *testing.T) {
	const data = "stream data (not encrypted)"
	tests := []struct {
		entries   string
		encrypted bool
	}{
		{"", true},
		{"/Filter /Crypt", false},
		{"/Filter [/Crypt] /DecodeParms [<< /Name /Identity >>]", false},
		{"/Filter /Crypt /DecodeParms << /Type /CryptFilterDecodeParms /Name /NoMethod >>", false},
		{"/Filter /Crypt /DecodeParms << /Name /SameMethod >>", true},
		{"/Filter [/Crypt] /DecodeParms [<< /Name /StdCF >>]", true},
	}
	original, err := os.ReadFile("../testfiles/encrypted/aes128_r4_crypt_filters.pdf")
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[uint32]string)
	for i, tt := range tests {
		objects[uint32(100+i)] = streamObject(tt.entries, data)
	}
	written, updated := appendEncrypted(t, original, objects)
	rdr := openEncryptedBytes(t, updated)

	for i, tt := range tests {
		id := uint32(100 + i)
		t.Run(tt.entries, func(t *testing.T) {
			if encrypted := !bytes.Contains(written[id], []byte(data)); encrypted != tt.encrypted {
				t.Errorf("stream encrypted = %v, want %v:\n%s", encrypted, tt.encrypted, written[id])
			}
			if got := readBackStream(t, rdr, id); got != data {
				t.Errorf("read back %q, want %q", got, data)
			}
		})
	}
}

func TestEncryptObjectCryptFilterErrors(t *testing.T) {
	rdr := openEncryptedReader(t, "../testfiles/encrypted/aes128_r4_crypt_filters.pdf")
	for _, entries := range []string{
		"/Filter /Crypt /DecodeParms << /Name /OtherMethod >>", // RC4, not the default AESV2
		"/Filter /Crypt /DecodeParms << /Name /Undefined >>",
		"/Filter 5 0 R",
		"/Filter [5 0 R]",
		"/Filter /Crypt /DecodeParms 5 0 R",
		"/Filter [/Crypt] /DecodeParms [6 0 R]",
	} {
		if _, err := encryptObject(rdr, 100, []byte(streamObject(entries, "x"))); err == nil {
			t.Errorf("encryptObject(%q): want error, got nil", entries)
		}
	}
}

// ISO 32000-2, 7.6.5: with /EncryptMetadata false only the metadata stream of
// the catalog stays unencrypted. aes128_r4_plain_metadata.pdf was created from
// testfile20.pdf with qpdf --encrypt pdfsign pdfsign 128 --use-aes=y
// --cleartext-metadata.
func TestEncryptObjectPlainMetadata(t *testing.T) {
	const xmp = "<x:xmpmeta xmlns:x='adobe:ns:meta/'/>"
	original, err := os.ReadFile("../testfiles/encrypted/aes128_r4_plain_metadata.pdf")
	if err != nil {
		t.Fatal(err)
	}
	rdr := openEncryptedBytes(t, original)
	if rdr.EncryptsMetadata() {
		t.Fatal("fixture encrypts its metadata")
	}
	catalogMetadata := rdr.Trailer().Key("Root").Key("Metadata").GetPtr().GetID()
	if catalogMetadata == 0 {
		t.Fatal("fixture has no catalog metadata stream")
	}
	const otherMetadata = 100

	metadata := streamObject("/Type /Metadata /Subtype /XML", xmp)
	written, updated := appendEncrypted(t, original, map[uint32]string{
		catalogMetadata: metadata,
		otherMetadata:   metadata,
	})
	if !bytes.Contains(written[catalogMetadata], []byte(xmp)) {
		t.Errorf("catalog metadata stream was encrypted:\n%s", written[catalogMetadata])
	}
	if bytes.Contains(written[otherMetadata], []byte(xmp)) {
		t.Errorf("metadata stream %d is not the one of the catalog but was not encrypted", otherMetadata)
	}
	rdr = openEncryptedBytes(t, updated)
	for _, id := range []uint32{catalogMetadata, otherMetadata} {
		if got := readBackStream(t, rdr, id); got != xmp {
			t.Errorf("stream %d read back as %q, want %q", id, got, xmp)
		}
	}
}

// ISO 32000-1, 7.6.1: the strings of the encryption dictionary are not encrypted.
func TestEncryptObjectKeepsEncryptionDictionary(t *testing.T) {
	rdr := openEncryptedReader(t, "../testfiles/encrypted/aes128_r4.pdf")
	encryptID := rdr.Trailer().Key("Encrypt").GetPtr().GetID()
	if encryptID == 0 {
		t.Fatal("fixture has no indirect encryption dictionary")
	}

	obj := []byte("<< /Filter /Standard /V 4 /R 4 /O (owner) /U (user) /P -1 >>")
	got, err := encryptObject(rdr, encryptID, obj)
	if err != nil {
		t.Fatalf("encryptObject: %v", err)
	}
	if !bytes.Equal(got, obj) {
		t.Errorf("encryptObject(%d) = %s, want the object unchanged", encryptID, got)
	}

	other, err := encryptObject(rdr, encryptID+1, obj)
	if err != nil {
		t.Fatalf("encryptObject: %v", err)
	}
	if bytes.Equal(other, obj) {
		t.Errorf("encryptObject(%d) left the object unchanged, want its strings encrypted", encryptID+1)
	}
}

func TestWriteObjectEncrypted(t *testing.T) {
	context := &SignContext{
		PDFReader:    openEncryptedReader(t, "../testfiles/encrypted/aes128_r4.pdf"),
		OutputBuffer: &filebuffer.Buffer{Buff: new(bytes.Buffer)},
	}

	if err := context.WriteObject(100, []byte("<< /T (Signature 1) >>")); err != nil {
		t.Fatalf("WriteObject: %v", err)
	}
	if got := context.OutputBuffer.Buff.String(); strings.Contains(got, "Signature 1") {
		t.Errorf("WriteObject wrote the string in clear text: %q", got)
	}

	if err := context.WriteObject(101, []byte("<< /T (unterminated >>")); err == nil {
		t.Error("WriteObject with a malformed object: want error, got nil")
	}
}

// FuzzEncryptObject checks that encryptObject does not panic on any input and
// that an object it accepts can still be parsed after encryption.
func FuzzEncryptObject(f *testing.F) {
	for _, seed := range []string{
		"<< /T (Signature 1) /Name <FEFF0628> /Empty () >>",
		`<< /A (a\)b\\c\n\101\0501) /B (x(y)z) /C (line\` + "\r\n" + `cont) >>`,
		"<< /A (x) % not a (string\r/B (y) >>",
		"[<41 4>]",
		"<< /Type /Annot /Rect [1 2.5 3 4] /P 3 0 R /MK << /CA (x) >> /Contents (note) >>",
		"<< /Type /Sig /ByteRange [0 0 0 0] /Contents<0000> /Name (John) >>",
		"<<\n  /Type /XObject\n  /Length 5\n>>\nstream\nhello\nendstream",
		"<< /Length 12 >>stream\r\n(endstream)\n\nendstream",
		"<< /Length 9223372036854775807 >>\nstream\nabc\nendstream",
		"<< /Filter [/Crypt] /DecodeParms [<< /Name /Identity >>] /Length 1 >>\nstream\nx\nendstream",
		"<< /Type /XRef /Length 3 >>\nstream\nabc\nendstream",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, object []byte) {
		out, err := encryptObject(fakeEncrypter{}, 7, object)
		if err != nil {
			return
		}
		if _, err := tokenizeObject(out); err != nil {
			t.Errorf("encrypted object %q does not parse: %v\ninput: %q", out, err, object)
		}
	})
}
