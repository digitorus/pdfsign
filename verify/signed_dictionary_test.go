package verify_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
)

var (
	referenceEntry = regexp.MustCompile(`(?s)\s*/Reference \[.*?\]`)
	lastStartxref  = regexp.MustCompile(`startxref\r?\n(\d+)\r?\n%%EOF\r?\n?$`)
)

// TestVerifyRedefinedSignatureDictionary certifies a document with pdfsign,
// then appends an incremental update that redefines the signature dictionary
// without its DocMDP transform, as an attacker would to turn a certification
// into an approval signature without touching the signed bytes. The verifier
// has to validate the dictionary the signature covers.
func TestVerifyRedefinedSignatureDictionary(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Certified Signer")

	signed := filepath.Join(t.TempDir(), "certified.pdf")
	if err := sign.SignFile("../testfiles/testfile20.pdf", signed, sign.SignData{
		Signature: sign.SignDataSignature{
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.DoNotAllowAnyChangesPerms,
		},
		Signer:            key,
		Certificate:       cert,
		CertificateChains: [][]*x509.Certificate{append([]*x509.Certificate{cert}, pki.Chain()...)},
		DigestAlgorithm:   crypto.SHA256,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	original, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}

	// The parser gives the signature object's number and the trailer
	// entries; only the object's text and the last startxref are taken from
	// the bytes, since the update has to carry a copy of that text.
	rdr, err := pdf.NewReader(bytes.NewReader(original), int64(len(original)))
	if err != nil {
		t.Fatalf("read signed file: %v", err)
	}
	trailer := rdr.Trailer()
	sig := trailer.Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
	objectNumber := sig.GetPtr().GetID()
	if objectNumber == 0 || sig.Key("Reference").IsNull() {
		t.Fatal("signature dictionary with a /Reference not found in the signed file")
	}
	rootPtr := trailer.Key("Root").GetPtr()

	object := regexp.MustCompile(fmt.Sprintf(`(?s)\n%d 0 obj\r?\n(.*?)\r?\nendobj`, objectNumber)).FindSubmatch(original)
	if object == nil {
		t.Fatalf("object %d not found in the signed file", objectNumber)
	}
	stripped := referenceEntry.ReplaceAllString(string(object[1]), "")
	if stripped == string(object[1]) {
		t.Fatal("no /Reference entry to strip from the signature dictionary")
	}

	prev := lastStartxref.FindSubmatch(original)
	if prev == nil {
		t.Fatal("startxref of the signed file not found")
	}

	// Revision 2: the redefined signature dictionary and a classic
	// cross-reference section chained to the signed revision.
	var tampered bytes.Buffer
	tampered.Write(original)
	if !bytes.HasSuffix(original, []byte("\n")) {
		tampered.WriteString("\n")
	}
	offset := tampered.Len()
	fmt.Fprintf(&tampered, "%d 0 obj\n%s\nendobj\n", objectNumber, stripped)
	xref := tampered.Len()
	fmt.Fprintf(&tampered, "xref\n0 1\n0000000000 65535 f \n%d 1\n%010d 00000 n \n", objectNumber, offset)
	fmt.Fprintf(&tampered, "trailer\n<< /Size %d /Root %d %d R /Prev %s >>\nstartxref\n%d\n%%%%EOF\n",
		trailer.Key("Size").Int64(), rootPtr.GetID(), rootPtr.GetGen(), string(prev[1]), xref)

	response, err := verify.VerifyWithOptions(bytes.NewReader(tampered.Bytes()), int64(tampered.Len()), verify.DefaultVerifyOptions())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(response.Signers) != 1 {
		t.Fatalf("got %d signers, want 1", len(response.Signers))
	}

	var messages []string
	for _, e := range response.Signers[0].ValidationErrors {
		messages = append(messages, e.Error())
	}
	joined := strings.Join(messages, "; ")
	if !strings.Contains(joined, "modified after signing: /Reference") {
		t.Errorf("the redefined signature dictionary was not reported: %s", joined)
	}
	if !strings.Contains(joined, "P=1") {
		t.Errorf("the signed DocMDP restriction was not enforced against the update: %s", joined)
	}
}
