package verify_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/verify"
)

var (
	fieldsEntry = regexp.MustCompile(`/Fields \[[^\]]*\]`)
	permsEntry  = regexp.MustCompile(`(?s)\s*/Perms <<.*?>>`)
)

// TestVerifyRemovedSignatureField certifies a document with pdfsign under
// form-filling permissions, adds an approval signature, then appends an
// incremental update that rewrites the catalog so that /AcroForm /Fields
// holds only the approval signature's field and /Perms is gone, as an
// attacker would to drop the certification and its permissions without
// touching any signed bytes. The verifier has to find the certification
// signature in the revision the approval signature covers and report it.
func TestVerifyRemovedSignatureField(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	certifierKey, certifierCert := pki.IssueLeaf("Certifier")
	approverKey, approverCert := pki.IssueLeaf("Approver")

	doc, err := pdfsign.OpenFile("../testfiles/testfile20.pdf")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	doc.Sign(certifierKey, certifierCert, pki.Chain()...).Type(pdfsign.CertificationSignature).Permission(pdfsign.AllowFormFilling)
	var certified bytes.Buffer
	if _, err := doc.Write(&certified); err != nil {
		t.Fatalf("certify: %v", err)
	}
	doc, err = pdfsign.Open(bytes.NewReader(certified.Bytes()), int64(certified.Len()))
	if err != nil {
		t.Fatalf("open certified: %v", err)
	}
	doc.Sign(approverKey, approverCert, pki.Chain()...).Type(pdfsign.ApprovalSignature)
	var signed bytes.Buffer
	if _, err := doc.Write(&signed); err != nil {
		t.Fatalf("approve: %v", err)
	}
	original := signed.Bytes()

	rdr, err := pdf.NewReader(bytes.NewReader(original), int64(len(original)))
	if err != nil {
		t.Fatalf("read signed file: %v", err)
	}
	trailer := rdr.Trailer()
	root := trailer.Key("Root")
	rootPtr := root.GetPtr()
	fields := root.Key("AcroForm").Key("Fields")
	if fields.Len() != 2 {
		t.Fatalf("got %d signature fields, want 2", fields.Len())
	}
	approvalField := fields.Index(1).GetPtr()

	// The catalog's text, from its latest definition in the file, with the
	// certification field and /Perms taken out.
	definitions := regexp.MustCompile(fmt.Sprintf(`(?s)\n%d 0 obj\r?\n(.*?)\r?\nendobj`, rootPtr.GetID())).FindAllSubmatch(original, -1)
	if definitions == nil {
		t.Fatalf("catalog object %d not found in the signed file", rootPtr.GetID())
	}
	catalog := string(definitions[len(definitions)-1][1])
	rewritten := fieldsEntry.ReplaceAllString(catalog, fmt.Sprintf("/Fields [%d 0 R]", approvalField.GetID()))
	rewritten = permsEntry.ReplaceAllString(rewritten, "")
	if rewritten == catalog || strings.Contains(rewritten, "/Perms") || !strings.Contains(catalog, "/Perms") {
		t.Fatalf("could not rewrite the catalog:\n%s", catalog)
	}
	prev := lastStartxref.FindSubmatch(original)
	if prev == nil {
		t.Fatal("startxref of the signed file not found")
	}

	var tampered bytes.Buffer
	tampered.Write(original)
	if !bytes.HasSuffix(original, []byte("\n")) {
		tampered.WriteString("\n")
	}
	offset := tampered.Len()
	fmt.Fprintf(&tampered, "%d 0 obj\n%s\nendobj\n", rootPtr.GetID(), rewritten)
	xref := tampered.Len()
	fmt.Fprintf(&tampered, "xref\n0 1\n0000000000 65535 f \n%d 1\n%010d 00000 n \n", rootPtr.GetID(), offset)
	fmt.Fprintf(&tampered, "trailer\n<< /Size %d /Root %d %d R /Prev %s >>\nstartxref\n%d\n%%%%EOF\n",
		trailer.Key("Size").Int64(), rootPtr.GetID(), rootPtr.GetGen(), string(prev[1]), xref)
	file := tampered.Bytes()

	// The tampered file's field tree reaches the approval signature only.
	current, err := pdf.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatalf("read tampered file: %v", err)
	}
	if n := current.Trailer().Key("Root").Key("AcroForm").Key("Fields").Len(); n != 1 {
		t.Fatalf("tampered file has %d fields, want 1", n)
	}

	response, err := verify.VerifyWithOptions(bytes.NewReader(file), int64(len(file)), verify.DefaultVerifyOptions())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(response.Signers) != 2 {
		t.Fatalf("got %d signers, want the approval and the recovered certification signature", len(response.Signers))
	}
	for i, signer := range response.Signers {
		var messages []string
		for _, e := range signer.ValidationErrors {
			messages = append(messages, e.Error())
		}
		joined := strings.Join(messages, "; ")
		unreachable := strings.Contains(joined, "not reachable from the current /AcroForm /Fields")
		if len(signer.Certificates) == 0 {
			t.Fatalf("signer %d has no certificate", i)
		}
		switch name := signer.Certificates[0].Certificate.Subject.CommonName; name {
		case "Approver":
			if unreachable {
				t.Errorf("the approval signature, which the field tree reaches, was reported unreachable: %s", joined)
			}
		case "Certifier":
			if !unreachable {
				t.Errorf("the removed certification signature was not reported: %s", joined)
			}
		default:
			t.Errorf("signer %d: unexpected certificate %q", i, name)
		}
		if !signer.ValidSignature {
			t.Errorf("%s: the signed bytes are intact but the signature did not verify: %s", signer.Certificates[0].Certificate.Subject.CommonName, joined)
		}
	}

	// The fluent API reports the same two signatures.
	doc, err = pdfsign.Open(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatalf("open tampered file: %v", err)
	}
	result := doc.Verify()
	if err := result.Err(); err != nil {
		t.Fatalf("fluent verify: %v", err)
	}
	if result.Count() != 2 {
		t.Fatalf("fluent verify found %d signatures, want 2", result.Count())
	}
	reported := false
	for _, sig := range result.Signatures() {
		for _, e := range sig.Errors {
			if strings.Contains(e.Error(), "not reachable from the current /AcroForm /Fields") {
				reported = true
			}
		}
	}
	if !reported || result.Valid() {
		t.Errorf("fluent verify: removed certification reported %v, valid %v; want reported and not valid", reported, result.Valid())
	}
}
