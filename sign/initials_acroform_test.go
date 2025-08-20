package sign

import (
	"bytes"
	"os"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/mattetti/filebuffer"
)

// TestLogInitialsAcroform opens testfiles/testfile50.pdf and logs AcroForm fields
func TestLogInitialsAcroform(t *testing.T) {
	f, err := os.Open("../testfiles/testfile50.pdf")
	if err != nil {
		t.Fatalf("failed to open test PDF: %v", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}

	rdr, err := pdf.NewReader(f, fi.Size())
	if err != nil {
		t.Fatalf("failed to create pdf reader: %v", err)
	}

	acro := rdr.Trailer().Key("Root").Key("AcroForm")
	if acro.IsNull() {
		t.Log("No AcroForm present")
		return
	}

	fields := acro.Key("Fields")
	if fields.IsNull() {
		t.Log("AcroForm present but no Fields array")
		return
	}

	// Log fields
	for i := 0; i < fields.Len(); i++ {
		field := fields.Index(i)
		nameVal := field.Key("T")
		valVal := field.Key("V")
		name := ""
		val := ""
		if !nameVal.IsNull() {
			name = nameVal.RawString()
		}
		if !valVal.IsNull() {
			val = valVal.RawString()
		}
		t.Logf("Field %d: T=%s V=%s", i, name, val)
	}

	// Now test the fillInitialsFields function in isolation. Use the signer
	// that is present in the test file ("jane.smith@example.com") and a
	// simple name to compute initials.
	signData := SignData{}
	signData.Signature.Info.Name = "Jane Smith"
	signData.Appearance.SignerUID = "jane.smith@example.com"

	ctx := SignContext{
		InputFile:    f,
		PDFReader:    rdr,
		OutputBuffer: filebuffer.New([]byte{}),
		SignData:     signData,
	}

	// Use the hex signer uid exactly as present in the PDF fields
	hexSigner := "6a616e652e736d697468406578616d706c652e636f6d"
	signData.Appearance.SignerUID = hexSigner
	ctx.SignData = signData

	if err := ctx.fillInitialsFields(); err != nil {
		t.Fatalf("fillInitialsFields failed: %v", err)
	}

	// Expected initials for "Jane Smith" => "JS"
	out := ctx.OutputBuffer.Buff.Bytes()
	if !bytes.Contains(out, []byte("(JS)")) {
		t.Fatalf("expected initials (JS) in updated objects, output buffer missing; buffer len=%d", len(out))
	}
}
