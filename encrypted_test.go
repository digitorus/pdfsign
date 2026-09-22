package pdfsign

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

// encryptedTestPassword is the user and owner password of the files in
// testfiles/encrypted, except rc4_r3_owner.pdf.
const encryptedTestPassword = "pdfsign"

// ownerTestPassword is the owner password of testfiles/encrypted/rc4_r3_owner.pdf,
// whose user password is encryptedTestPassword.
const ownerTestPassword = "pdfsign-owner"

// encryptedOutputDir is not testfiles/success: the CI workflow validates
// everything there with pdfcpu, which cannot open an encrypted document.
const encryptedOutputDir = "testfiles/encrypted_output"

func TestOpenFileEncryptedRequiresPassword(t *testing.T) {
	if _, err := OpenFile("testfiles/encrypted/aes256_r5.pdf"); err == nil {
		t.Fatal("OpenFile on a password protected document: want error, got nil")
	}
	if _, err := OpenFileWithPassword("testfiles/encrypted/aes256_r5.pdf", "wrong"); err == nil {
		t.Fatal("OpenFileWithPassword with a wrong password: want error, got nil")
	}
}

func TestSignEncryptedDocument(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	keyAlice, certAlice := pki.IssueLeaf("Alice")
	keyBob, certBob := pki.IssueLeaf("Bob")

	for _, tc := range []struct {
		name, password string
	}{
		{"aes128_r4.pdf", encryptedTestPassword},
		{"aes256_r5.pdf", encryptedTestPassword},
		{"aes256_r6.pdf", encryptedTestPassword},
		{"aes128_r4_plain_metadata.pdf", encryptedTestPassword},
		{"aes128_r4_crypt_filters.pdf", encryptedTestPassword},
		{"rc4_r3_owner.pdf", ownerTestPassword},
	} {
		name := tc.name
		t.Run(name, func(t *testing.T) {
			doc, err := OpenFileWithPassword("testfiles/encrypted/"+name, tc.password)
			if err != nil {
				t.Fatalf("OpenFileWithPassword: %v", err)
			}

			// Two staged signatures: the second pass signs the re-opened
			// output of the first one.
			doc.Sign(keyAlice, certAlice, pki.Chain()...).Reason("First (Alice)")
			doc.Sign(keyBob, certBob, pki.Chain()...).Reason("Second (Bob)")

			var out bytes.Buffer
			if _, err := doc.Write(&out); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if testing.Verbose() {
				if err := os.MkdirAll(encryptedOutputDir, 0o755); err != nil {
					t.Error(err)
				} else if err := os.WriteFile(filepath.Join(encryptedOutputDir, "encrypted_fluent_"+name), out.Bytes(), 0o644); err != nil {
					t.Error(err)
				}
			}

			signed, err := OpenWithPassword(bytes.NewReader(out.Bytes()), int64(out.Len()), tc.password)
			if err != nil {
				t.Fatalf("OpenWithPassword on signed document: %v", err)
			}
			vr := signed.Verify().TrustSelfSigned(true)
			if err := vr.Err(); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if vr.Count() != 2 {
				t.Fatalf("expected 2 signatures, got %d", vr.Count())
			}
			for i, want := range []string{"First (Alice)", "Second (Bob)"} {
				sig := vr.Signatures()[i]
				if sig.Reason != want {
					t.Errorf("signature %d: reason %q, want %q", i, sig.Reason, want)
				}
				if len(sig.Errors) > 0 {
					t.Errorf("signature %d: errors %v", i, sig.Errors)
				}
			}
			if !vr.Valid() {
				t.Error("signatures are not valid")
			}

			n := 0
			for sig, err := range signed.Signatures() {
				if err != nil {
					t.Fatalf("Signatures: %v", err)
				}
				if len(sig.Contents()) == 0 || sig.Contents()[0] != 0x30 {
					t.Errorf("signature %d: Contents is not a DER encoded CMS structure", n)
				}
				n++
			}
			if n != 2 {
				t.Errorf("Signatures() returned %d signatures, want 2", n)
			}
		})
	}
}
