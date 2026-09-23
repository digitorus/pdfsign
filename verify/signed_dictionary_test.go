package verify_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
)

var (
	signatureObject = regexp.MustCompile(`(?s)\n(\d+) 0 obj\n(<<\n /Type /Sig\n.*?)\nendobj\n`)
	referenceEntry  = regexp.MustCompile(`(?s)\s*/Reference \[.*?\]`)
	lastStartxref   = regexp.MustCompile(`startxref\r?\n(\d+)\r?\n%%EOF\r?\n?$`)
	trailerRoot     = regexp.MustCompile(`/Root (\d+ \d+ R)`)
	trailerSize     = regexp.MustCompile(`/Size (\d+)`)
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

	m := signatureObject.FindSubmatch(original)
	if m == nil {
		t.Fatal("signature dictionary not found in the signed file")
	}
	objectNumber, _ := strconv.Atoi(string(m[1]))
	stripped := referenceEntry.ReplaceAllString(string(m[2]), "")
	if stripped == string(m[2]) {
		t.Fatal("no /Reference entry to strip from the signature dictionary")
	}

	prev := lastStartxref.FindSubmatch(original)
	root := trailerRoot.FindAll(original, -1)
	size := trailerSize.FindAll(original, -1)
	if prev == nil || root == nil || size == nil {
		t.Fatal("trailer of the signed file not found")
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
	fmt.Fprintf(&tampered, "trailer\n<< %s %s /Prev %s >>\nstartxref\n%d\n%%%%EOF\n",
		string(size[len(size)-1]), string(root[len(root)-1]), string(prev[1]), xref)

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
