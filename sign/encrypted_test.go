package sign_test

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/sign"
)

// encryptedTestPassword is the user and owner password of the files in
// testfiles/encrypted, encrypted versions of testfile17.pdf.
const encryptedTestPassword = "pdfsign"

// encryptedOutputDir is not testfiles/success: the CI workflow validates
// everything there with pdfcpu, which cannot open an encrypted document.
const encryptedOutputDir = "../testfiles/encrypted_output"

func openEncrypted(t *testing.T, path string) (*os.File, *pdf.Reader, int64) {
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
	rdr, err := pdf.NewReaderEncrypted(f, info.Size(), passwordOnce(encryptedTestPassword))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return f, rdr, info.Size()
}

func passwordOnce(password string) func() string {
	used := false
	return func() string {
		if used {
			return ""
		}
		used = true
		return password
	}
}

func TestSignEncryptedPDF(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}

	files := []string{
		"aes128_r4.pdf", // AES-128, V4 R4 (AESV2), xref table, created with qpdf
		"aes256_r5.pdf", // AES-256, V5 R5 (AESV3), xref and object streams, created with pdfcpu
		"aes256_r6.pdf", // AES-256, V5 R6 (AESV3), xref table, created with qpdf
	}

	for _, name := range files {
		for _, visible := range []bool{false, true} {
			testName := name + "/invisible"
			if visible {
				testName = name + "/visible"
			}
			t.Run(testName, func(t *testing.T) {
				input, rdr, size := openEncrypted(t, filepath.Join("../testfiles/encrypted", name))

				signData := sign.SignData{
					Signature: sign.SignDataSignature{
						Info: sign.SignDataSignatureInfo{
							Name:        "John Doe",
							Location:    "Somewhere",
							Reason:      "Encrypted document test",
							ContactInfo: "None",
							Date:        time.Now().Local(),
						},
						CertType:   sign.ApprovalSignature,
						DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
					},
					Appearance: sign.Appearance{
						Visible:     visible,
						LowerLeftX:  400,
						LowerLeftY:  50,
						UpperRightX: 600,
						UpperRightY: 125,
					},
					DigestAlgorithm: crypto.SHA256,
					Signer:          pkey,
					Certificate:     cert,
				}

				var out bytes.Buffer
				if err := sign.Sign(input, &out, rdr, size, signData); err != nil {
					t.Fatalf("sign: %v", err)
				}
				signed := out.Bytes()
				if testing.Verbose() {
					outName := strings.ReplaceAll(strings.TrimSuffix(testName, ".pdf"), "/", "_") + "_signed.pdf"
					if err := writeSignedOutput(encryptedOutputDir, outName, signed); err != nil {
						t.Error(err)
					}
				}

				// Strings and streams added by the incremental update must be
				// encrypted, so none of the values may appear in clear text.
				update := signed[size:]
				for _, plain := range []string{"John Doe", "Somewhere", "Encrypted document test", "Signature 1", "(D:"} {
					if bytes.Contains(update, []byte(plain)) {
						t.Errorf("incremental update contains %q in clear text", plain)
					}
				}

				doc, err := pdfsign.OpenWithPassword(bytes.NewReader(signed), int64(len(signed)), encryptedTestPassword)
				if err != nil {
					t.Fatalf("OpenWithPassword on signed document: %v", err)
				}
				vr := doc.Verify().TrustSelfSigned(true)
				if err := vr.Err(); err != nil {
					t.Fatalf("verify: %v", err)
				}
				if vr.Count() != 1 {
					t.Fatalf("found %d signatures, want 1", vr.Count())
				}
				signer := vr.Signatures()[0]
				if !signer.Valid {
					t.Errorf("signature is not valid: %v", signer.Errors)
				}
				if signer.SignerName != "John Doe" || signer.Location != "Somewhere" || signer.Reason != "Encrypted document test" {
					t.Errorf("signer info = %q/%q/%q, want the values used for signing", signer.SignerName, signer.Location, signer.Reason)
				}
			})
		}
	}
}

// writeSignedOutput saves a signed document for inspection after a verbose run.
func writeSignedOutput(dir, name string, signed []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), signed, 0o644)
}
