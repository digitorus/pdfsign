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
// form-filling permissions and adds an approval signature, then appends an
// incremental update that rewrites the catalog so that /AcroForm /Fields
// holds one of the two signature fields only, as an attacker would to drop a
// signature without touching any signed bytes: the certification with its
// permissions, or the approval that followed it. The verifier has to find
// the dropped signature in the revision that held it and report it.
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
	rootPtr := trailer.Key("Root").GetPtr()
	fields := trailer.Key("Root").Key("AcroForm").Key("Fields")
	if fields.Len() != 2 {
		t.Fatalf("got %d signature fields, want 2", fields.Len())
	}
	catalog := objectText(t, original, rootPtr.GetID())
	if !strings.Contains(catalog, "/Perms") {
		t.Fatalf("the catalog carries no /Perms:\n%s", catalog)
	}

	// The kept signature stays valid in both cases: the approval signature
	// has no permissions to enforce, and the certification's form-filling
	// permission sees the same fields in the current document as in the
	// revision it signed, the approval's field having come and gone since.
	for _, tc := range []struct {
		name      string
		keep      int    // the index in /Fields of the field the update keeps
		dropPerms bool   // whether the update drops the catalog /Perms as well
		removed   string // the signer name of the signature the update drops
	}{
		{"the certification field is dropped", 1, true, "Certifier"},
		{"the approval field is dropped", 0, false, "Approver"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rewritten := fieldsEntry.ReplaceAllString(catalog, fmt.Sprintf("/Fields [%d 0 R]", fields.Index(tc.keep).GetPtr().GetID()))
			if tc.dropPerms {
				rewritten = permsEntry.ReplaceAllString(rewritten, "")
			}
			if rewritten == catalog || strings.Contains(rewritten, "/Perms") == tc.dropPerms {
				t.Fatalf("could not rewrite the catalog:\n%s", catalog)
			}
			file := appendUpdate(t, original, trailer, rootPtr.GetID(), rewritten)

			// The tampered file's field tree reaches one signature only.
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
				t.Fatalf("got %d signers, want the kept and the removed signature", len(response.Signers))
			}
			for i, signer := range response.Signers {
				var messages []string
				for _, e := range signer.ValidationErrors {
					messages = append(messages, e.Error())
				}
				joined := strings.Join(messages, "; ")
				reported := strings.Contains(joined, "not reachable from the current /AcroForm /Fields") ||
					strings.Contains(joined, "/Perms names a certification signature")
				name := signer.Name
				switch {
				case name != "Certifier" && name != "Approver":
					t.Errorf("signer %d has an unexpected name %q", i, name)
				case name == tc.removed && !reported:
					t.Errorf("the removed %s signature was not reported: %s", name, joined)
				case name == tc.removed && signer.ValidSignature:
					t.Errorf("the removed %s signature is reported as valid", name)
				case name != tc.removed && reported:
					t.Errorf("the kept %s signature was reported as removed: %s", name, joined)
				case name != tc.removed && !signer.ValidSignature:
					t.Errorf("the kept %s signature did not verify: %s", name, joined)
				}
			}

			// The fluent API reports the same two signatures.
			doc, err := pdfsign.Open(bytes.NewReader(file), int64(len(file)))
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
					if strings.Contains(e.Error(), "not reachable from the current /AcroForm /Fields") || strings.Contains(e.Error(), "/Perms names a certification signature") {
						reported = true
					}
				}
			}
			if !reported || result.Valid() {
				t.Errorf("fluent verify: removed signature reported %v, valid %v; want reported and not valid", reported, result.Valid())
			}
		})
	}
}
