package verify_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/verify"
)

// BenchmarkVerify measures VerifyWithOptions over documents that differ in
// what the verifier has to read: one certification signature (two
// revisions), five signatures (six revisions), one signature followed by
// fifty trivial incremental updates (fifty-two revisions), and the
// repository's three-field file. The signed fixtures are built in-process
// with a self-signed key, so the numbers cover parsing, hashing and
// signature verification, not certificate chain building.
func BenchmarkVerify(b *testing.B) {
	key, cert := benchmarkSigner(b)
	original, err := os.ReadFile("../testfiles/testfile20.pdf")
	if err != nil {
		b.Fatal(err)
	}
	multi, err := os.ReadFile("../testfiles/testfile_multi.pdf")
	if err != nil {
		b.Fatal(err)
	}

	certified := benchmarkSign(b, original, key, cert, pdfsign.CertificationSignature)
	five := certified
	for i := 0; i < 4; i++ {
		five = benchmarkSign(b, five, key, cert, pdfsign.ApprovalSignature)
	}
	updated := certified
	for i := 0; i < 50; i++ {
		rdr, err := pdf.NewReader(bytes.NewReader(updated), int64(len(updated)))
		if err != nil {
			b.Fatal(err)
		}
		trailer := rdr.Trailer()
		updated = appendUpdate(b, updated, trailer, uint32(trailer.Key("Size").Int64()),
			fmt.Sprintf("<< /Type /Annot /Subtype /Square /Rect [0 0 %d 10] >>", i+1))
	}

	for _, c := range []struct {
		name string
		file []byte
	}{
		{"certified", certified},
		{"five-signatures", five},
		{"fifty-updates", updated},
		{"testfile_multi", multi},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.file)))
			for b.Loop() {
				if _, err := verify.VerifyWithOptions(bytes.NewReader(c.file), int64(len(c.file)), verify.DefaultVerifyOptions()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchmarkSigner returns a self-signed signing key and certificate.
func benchmarkSigner(b *testing.B) (crypto.Signer, *x509.Certificate) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Benchmark Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return key, cert
}

// benchmarkSign returns the document signed with a PAdES-B signature, which
// embeds no revocation data, so no server is needed; a certification
// signature permits form filling.
func benchmarkSign(b *testing.B, in []byte, key crypto.Signer, cert *x509.Certificate, sigType pdfsign.SignatureType) []byte {
	b.Helper()
	doc, err := pdfsign.Open(bytes.NewReader(in), int64(len(in)))
	if err != nil {
		b.Fatal(err)
	}
	signer := doc.Sign(key, cert).Type(sigType).Format(pdfsign.PAdES_B)
	if sigType == pdfsign.CertificationSignature {
		signer.Permission(pdfsign.AllowFormFilling)
	}
	var out bytes.Buffer
	if _, err := doc.Write(&out); err != nil {
		b.Fatal(err)
	}
	return out.Bytes()
}
