package sign_test

import (
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/sign"
)

// TestCertificationSignatureSetsPermsDocMDP covers ISO 32000-1 12.8.2.2: a
// certification signature is only a certification signature if the document
// catalog's /Perms dictionary has a /DocMDP entry pointing at the signature.
//
// Writing /P into the signature dictionary's /Reference is not enough on its own
// — that states the permission level, while /Perms is what makes a conforming
// reader apply it. A file with /P but no /Perms is read as an ordinary approval
// signature, which is silent: it still verifies, and tools that report the
// signature type report it as certified.
func TestCertificationSignatureSetsPermsDocMDP(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Certification Signature Test")

	for _, tc := range []struct {
		name      string
		certType  sign.CertType
		wantPerms bool
	}{
		{"certification", sign.CertificationSignature, true},
		{"approval", sign.ApprovalSignature, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "signed.pdf")
			err := sign.SignFile("../testfiles/testfile20.pdf", out, sign.SignData{
				Signature: sign.SignDataSignature{
					CertType:   tc.certType,
					DocMDPPerm: sign.DoNotAllowAnyChangesPerms,
				},
				Signer:            key,
				Certificate:       cert,
				CertificateChains: [][]*x509.Certificate{append([]*x509.Certificate{cert}, pki.Chain()...)},
				DigestAlgorithm:   crypto.SHA256,
			})
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			f, err := os.Open(out)
			if err != nil {
				t.Fatalf("open signed file: %v", err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			rdr, err := pdf.NewReader(f, info.Size())
			if err != nil {
				t.Fatalf("read signed file: %v", err)
			}

			perms := rdr.Trailer().Key("Root").Key("Perms")
			if !tc.wantPerms {
				if !perms.IsNull() {
					t.Errorf("%s signature wrote /Perms; only a certification signature may", tc.certType)
				}
				return
			}
			if perms.IsNull() {
				t.Fatal("certification signature has no catalog /Perms — readers will treat it as an approval signature")
			}

			// /Perms /DocMDP must be the signature dictionary itself, not merely
			// present: a dangling or mistargeted reference is worse than none.
			docMDP := perms.Key("DocMDP")
			if docMDP.IsNull() {
				t.Fatal("/Perms is present but carries no /DocMDP entry")
			}
			if got := docMDP.Key("Type").Name(); got != "Sig" {
				t.Errorf("/Perms /DocMDP points at a /Type /%s object, want /Sig", got)
			}
			transform := docMDP.Key("Reference").Index(0)
			if got := transform.Key("TransformMethod").Name(); got != "DocMDP" {
				t.Errorf("signature /Reference /TransformMethod = /%s, want /DocMDP", got)
			}
			if got := transform.Key("TransformParams").Key("P").Int64(); got != 1 {
				t.Errorf("/TransformParams /P = %d, want 1 (DoNotAllowAnyChangesPerms)", got)
			}
		})
	}
}
