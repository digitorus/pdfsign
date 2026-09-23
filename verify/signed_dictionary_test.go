package verify_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/verify"
)

var referenceEntry = regexp.MustCompile(`(?s)\s*/Reference \[.*?\]`)

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

	doc, err := pdfsign.OpenFile("../testfiles/testfile20.pdf")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	doc.Sign(key, cert, pki.Chain()...).Type(pdfsign.CertificationSignature).Permission(pdfsign.NoChanges)
	var certified bytes.Buffer
	if _, err := doc.Write(&certified); err != nil {
		t.Fatalf("sign: %v", err)
	}
	original := certified.Bytes()

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

	object := objectText(t, original, objectNumber)
	stripped := referenceEntry.ReplaceAllString(object, "")
	if stripped == object {
		t.Fatal("no /Reference entry to strip from the signature dictionary")
	}

	// Revision 2: the redefined signature dictionary.
	tampered := appendUpdate(t, original, trailer, objectNumber, stripped)

	response, err := verify.VerifyWithOptions(bytes.NewReader(tampered), int64(len(tampered)), verify.DefaultVerifyOptions())
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
