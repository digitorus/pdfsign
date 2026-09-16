package pdfsign_test

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/ocspx"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pkcs7"
)

var oidAttributeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

func TestPQCOnlySignatureStructure(t *testing.T) {
	pki := testpki.NewTestPKIWithConfig(t, testpki.TestPKIConfig{
		Profile:         testpki.MLDSA_65,
		IntermediateCAs: 1,
	})
	defer pki.Close()
	pki.StartCRLServer()

	privateKey, certificate := pki.IssueLeaf("PQC PDF Signer")
	tsaURL := pki.StartMockTSA()
	doc, err := pdfsign.OpenFile("testfiles/testfile12.pdf")
	if err != nil {
		t.Fatal(err)
	}
	doc.Sign(privateKey, certificate, pki.Chain()...).
		Format(pdfsign.PAdES_B_T).
		Timestamp(tsaURL)

	var output bytes.Buffer
	if _, err := doc.Write(&output); err != nil {
		t.Fatalf("sign PQC PDF: %v", err)
	}

	signed, err := pdfsign.Open(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	result := signed.Verify().
		TrustedRoots(pki.RootPool()).
		AllowedAlgorithms(x509.MLDSA).
		ValidateFullChain(true).
		ValidateTimestampCertificates(true).
		ExternalChecks(true)
	if !result.Valid() {
		t.Fatalf("PQC signature invalid: %v", result.Signatures()[0].Errors)
	}
	if !result.Signatures()[0].TimestampValid {
		t.Fatalf("PQC timestamp invalid: %v", result.Signatures()[0].Warnings)
	}

	var signatureCMS []byte
	for signature, err := range signed.Signatures() {
		if err != nil {
			t.Fatal(err)
		}
		if signature.SubFilter() != "ETSI.CAdES.detached" {
			t.Fatalf("SubFilter = %q, want ETSI.CAdES.detached", signature.SubFilter())
		}
		signatureCMS = signature.Contents()
		break
	}
	assertMLDSACMS(t, signatureCMS, mldsa.MLDSA65().SignatureSize())

	p7, err := pkcs7.Parse(signatureCMS)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range p7.Certificates {
		assertMLDSACertificate(t, cert)
	}

	var timestampToken []byte
	for _, attribute := range p7.Signers[0].UnauthenticatedAttributes {
		if attribute.Type.Equal(oidAttributeTimeStampToken) {
			timestampToken = attribute.Value.Bytes
			break
		}
	}
	if len(timestampToken) == 0 {
		t.Fatal("signature has no RFC 3161 timestamp token")
	}
	assertMLDSACMS(t, timestampToken, mldsa.MLDSA65().SignatureSize())
	timestampCMS, err := pkcs7.Parse(timestampToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range timestampCMS.Certificates {
		assertMLDSACertificate(t, cert)
	}

	crl, err := x509.ParseRevocationList(pki.CRLBytes)
	if err != nil {
		t.Fatal(err)
	}
	if crl.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("CRL signature = %s, want ML-DSA-65", crl.SignatureAlgorithm)
	}
	if err := crl.CheckSignatureFrom(pki.IntermediateCerts[0]); err != nil {
		t.Fatalf("verify ML-DSA CRL: %v", err)
	}

	if pki.OCSPRequestHash != crypto.SHA512 {
		t.Fatalf("OCSP request hash = %s, want SHA-512", pki.OCSPRequestHash)
	}
	ocspResponse, err := ocspx.ParseResponseForCert(pki.OCSPBytes, certificate, pki.IntermediateCerts[0])
	if err != nil {
		t.Fatal(err)
	}
	if ocspResponse.IssuerHash != crypto.SHA512 {
		t.Fatalf("OCSP CertID hash = %s, want SHA-512", ocspResponse.IssuerHash)
	}
	if ocspResponse.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("OCSP response signature = %s, want ML-DSA-65", ocspResponse.SignatureAlgorithm)
	}
	tamperedOCSP := append([]byte(nil), pki.OCSPBytes...)
	tamperedOCSP[len(tamperedOCSP)-1] ^= 1
	if _, err := ocspx.ParseResponseForCert(tamperedOCSP, certificate, pki.IntermediateCerts[0]); err == nil {
		t.Fatal("tampered ML-DSA OCSP response was accepted")
	}
}

func TestMLDSARejectsMismatchedCMSDigest(t *testing.T) {
	pki := testpki.NewTestPKIWithConfig(t, testpki.TestPKIConfig{
		Profile:         testpki.MLDSA_44,
		IntermediateCAs: 1,
	})
	defer pki.Close()
	pki.StartCRLServer()
	privateKey, certificate := pki.IssueLeaf("PQC PDF Signer")

	doc, err := pdfsign.OpenFile("testfiles/testfile12.pdf")
	if err != nil {
		t.Fatal(err)
	}
	doc.Sign(privateKey, certificate, pki.Chain()...).
		Format(pdfsign.PAdES_B).
		Digest(crypto.SHA256)

	var output bytes.Buffer
	if _, err := doc.Write(&output); err == nil {
		t.Fatal("ML-DSA signature with mismatched SHA-256 /DigestMethod was accepted")
	}
}

func assertMLDSACMS(t *testing.T, der []byte, signatureSize int) {
	t.Helper()
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	if len(p7.Signers) != 1 {
		t.Fatalf("CMS signer count = %d, want 1", len(p7.Signers))
	}
	signer := p7.Signers[0]
	if !signer.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA512) {
		t.Fatalf("CMS digest = %s, want SHA-512", signer.DigestAlgorithm.Algorithm)
	}
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDSignatureAlgorithmMLDSA65) {
		t.Fatalf("CMS signature algorithm = %s, want ML-DSA-65", signer.DigestEncryptionAlgorithm.Algorithm)
	}
	if len(signer.DigestEncryptionAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("ML-DSA AlgorithmIdentifier parameters must be absent")
	}
	if len(signer.EncryptedDigest) != signatureSize {
		t.Fatalf("ML-DSA signature length = %d, want %d", len(signer.EncryptedDigest), signatureSize)
	}
}

func assertMLDSACertificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if cert.PublicKeyAlgorithm != x509.MLDSA {
		t.Fatalf("certificate public key algorithm = %s, want ML-DSA", cert.PublicKeyAlgorithm)
	}
	if cert.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("certificate signature algorithm = %s, want ML-DSA-65", cert.SignatureAlgorithm)
	}
}
