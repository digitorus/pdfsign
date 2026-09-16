package sign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

// fakeEncrypter makes the encryption visible in test output: it prefixes the
// data with the object number and reverses it.
type fakeEncrypter struct{}

func (fakeEncrypter) Trailer() pdf.Value { return pdf.Value{} }

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
		"<< /Length 4 0 R >>\nstream\nabcd\nendstream", // indirect Length
		"<< /Length 10 >>\nstream\nabc\nendstream",     // Length beyond the data
		"<< /T (unterminated >>",
		"<< /T <4142 >>",
	} {
		if _, err := encryptObject(fakeEncrypter{}, 1, []byte(in)); err == nil {
			t.Errorf("encryptObject(%q): want error, got nil", in)
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
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	offered := false
	rdr, err := pdf.NewReaderEncrypted(f, info.Size(), func() string {
		if offered {
			return ""
		}
		offered = true
		return "pdfsign"
	})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return rdr
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
