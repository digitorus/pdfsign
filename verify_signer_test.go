package pdfsign_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// The certificate bag is unsigned CMS metadata. A trusted certificate in it
// must never confer trust or identity on a signature made by a different key.
func TestVerify_CMSSignerIdentity(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	issuer := pki.IntermediateCerts[0]
	issuerKey := pki.IntermediateKeys[0]
	victimKey, victim := cmsTestCertificate(t, "Trusted victim", 10, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	actualKey, actual := cmsTestCertificate(t, "Actual trusted signer", 11, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	attackerKey, attacker := cmsTestCertificate(t, "Untrusted attacker", 20, nil, nil, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	badKUKey, badKU := cmsTestCertificate(t, "Wrong key usage", 30, issuer, issuerKey, x509.KeyUsageKeyEncipherment, x509.ExtKeyUsageEmailProtection)
	badEKUKey, badEKU := cmsTestCertificate(t, "Wrong extended key usage", 40, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageServerAuth)
	collisionKey, collision := cmsTestCertificate(t, "Ambiguous identity", 10, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)

	for _, tc := range []struct {
		name                   string
		key                    crypto.Signer
		cert                   *x509.Certificate
		permissive             bool
		config                 pkcs7.SignerInfoConfig
		extraSigner            bool
		noSigners              bool
		malformed              bool
		wantValid, wantTrusted bool
		wantIdentity           bool
		wantPolicy             bool
	}{
		{name: "trusted decoy before untrusted signer", key: attackerKey, cert: attacker, wantIdentity: true},
		{name: "trusted signer after decoy and CAs", key: actualKey, cert: actual, wantValid: true, wantTrusted: true, wantIdentity: true},
		{name: "explicit embedded trust still reports actual signer", key: attackerKey, cert: attacker, permissive: true, wantValid: true, wantIdentity: true},
		{name: "signer key usage cannot borrow decoy policy", key: badKUKey, cert: badKU, wantTrusted: true, wantIdentity: true, wantPolicy: true},
		{name: "signer EKU cannot borrow decoy policy", key: badEKUKey, cert: badEKU, wantTrusted: true, wantIdentity: true, wantPolicy: true},
		{name: "missing signer certificate", key: attackerKey, cert: attacker, config: pkcs7.SignerInfoConfig{SkipCertificates: true}},
		{name: "multiple CMS signers", key: attackerKey, cert: attacker, extraSigner: true},
		{name: "no CMS signers", key: attackerKey, cert: attacker, noSigners: true},
		{name: "malformed CMS is an invalid result", key: attackerKey, cert: attacker, malformed: true},
		{name: "conflicting certificates share signer identifier", key: collisionKey, cert: collision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := cmsTestPDF(t, func(content []byte) []byte {
				if tc.malformed {
					return []byte{0x30, 0x00}
				}
				sd, err := pkcs7.NewSignedData(content)
				if err != nil {
					t.Fatal(err)
				}
				sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
				sd.AddCertificate(victim)
				for _, cert := range pki.Chain() {
					sd.AddCertificate(cert)
				}
				if err := sd.AddSigner(tc.cert, tc.key, tc.config); err != nil {
					t.Fatal(err)
				}
				if tc.extraSigner {
					if err := sd.AddSigner(victim, victimKey, pkcs7.SignerInfoConfig{}); err != nil {
						t.Fatal(err)
					}
				}
				sd.Detach()
				if tc.noSigners {
					sd.GetSignedData().SignerInfos = nil
				}
				der, err := sd.Finish()
				if err != nil {
					t.Fatal(err)
				}
				return der
			})
			doc, err := pdfsign.Open(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			result := doc.Verify().TrustedRoots(pki.RootPool()).TrustSelfSigned(tc.permissive)
			if err := result.Err(); err != nil {
				t.Fatal(err)
			}
			if result.Valid() != tc.wantValid {
				t.Errorf("Valid=%v, want %v", result.Valid(), tc.wantValid)
			}
			sigs := result.Signatures()
			if len(sigs) != 1 {
				t.Fatalf("got %d signatures, want 1", len(sigs))
			}
			if sigs[0].TrustedChain != tc.wantTrusted {
				t.Errorf("TrustedChain=%v, want %v", sigs[0].TrustedChain, tc.wantTrusted)
			}
			if tc.wantIdentity {
				if sigs[0].Certificate == nil || !sigs[0].Certificate.Equal(tc.cert) {
					t.Error("reported certificate is not the CMS signer")
				}
			} else if sigs[0].Certificate != nil {
				t.Error("ambiguous/missing signer must not report a certificate")
			}
			if tc.wantPolicy {
				var policyErr *verify.PolicyError
				if !errors.As(errors.Join(sigs[0].Errors...), &policyErr) {
					t.Errorf("expected policy error, got %v", sigs[0].Errors)
				}
			}
			if !tc.wantValid && len(sigs[0].Errors) == 0 {
				t.Error("rejected signature has no validation error")
			}

			options := verify.DefaultVerifyOptions() //nolint:staticcheck // Regression coverage for the supported legacy API.
			options.TrustedRoots = pki.RootPool()
			options.AllowUntrustedRoots = tc.permissive
			legacy, err := verify.VerifyWithOptions(bytes.NewReader(data), int64(len(data)), options) //nolint:staticcheck // Exercise the legacy verification entry point.
			if err != nil {
				t.Fatal(err)
			}
			if len(legacy.Signers) != 1 {
				t.Fatalf("legacy returned %d signers", len(legacy.Signers))
			}
			signer := legacy.Signers[0]
			if (signer.ValidSignature && len(signer.ValidationErrors) == 0) != tc.wantValid {
				t.Errorf("legacy validity mismatch: %+v", signer)
			}
			if signer.TrustedIssuer != tc.wantTrusted {
				t.Errorf("legacy TrustedIssuer=%v, want %v", signer.TrustedIssuer, tc.wantTrusted)
			}
			if tc.wantIdentity && (len(signer.Certificates) == 0 || !signer.Certificates[0].Certificate.Equal(tc.cert)) {
				t.Error("legacy first certificate is not the CMS signer")
			}
		})
	}
}

func TestVerify_CMSTimestampSignerIdentity(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	issuer, issuerKey := pki.IntermediateCerts[0], pki.IntermediateKeys[0]
	key, cert := cmsTestCertificate(t, "PDF signer", 50, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	_, decoy := cmsTestCertificate(t, "Trusted TSA decoy", 60, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageTimeStamping)
	trustedKey, trusted := cmsTestCertificate(t, "Actual trusted TSA", 70, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageTimeStamping)
	untrustedKey, untrusted := cmsTestCertificate(t, "Actual untrusted TSA", 80, nil, nil, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageTimeStamping)
	wrongEKUKey, wrongEKU := cmsTestCertificate(t, "Actual TSA with wrong EKU", 90, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	for _, tc := range []struct {
		name    string
		key     crypto.Signer
		cert    *x509.Certificate
		trusted bool
	}{
		{"untrusted TSA cannot borrow decoy trust", untrustedKey, untrusted, false},
		{"trusted TSA after decoy is accepted", trustedKey, trusted, true},
		{"actual TSA must have timestamp EKU", wrongEKUKey, wrongEKU, false},
	} {
		for _, documentTimestamp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/documentTimestamp=%v", tc.name, documentTimestamp), func(t *testing.T) {
				subFilter := "adbe.pkcs7.detached"
				if documentTimestamp {
					subFilter = "ETSI.RFC3161"
				}
				data := cmsTestPDFWithSubFilter(t, subFilter, func(content []byte) []byte {
					if documentTimestamp {
						return cmsTestTimestamp(t, content, tc.key, tc.cert, append([]*x509.Certificate{decoy}, pki.Chain()...))
					}
					sd, err := pkcs7.NewSignedData(content)
					if err != nil {
						t.Fatal(err)
					}
					sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
					for _, c := range pki.Chain() {
						sd.AddCertificate(c)
					}
					if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
						t.Fatal(err)
					}
					si := &sd.GetSignedData().SignerInfos[0]
					token := cmsTestTimestamp(t, si.EncryptedDigest, tc.key, tc.cert, append([]*x509.Certificate{decoy}, pki.Chain()...))
					if err := si.SetUnauthenticatedAttributes([]pkcs7.Attribute{{
						Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}, Value: asn1.RawValue{FullBytes: token},
					}}); err != nil {
						t.Fatal(err)
					}
					sd.Detach()
					der, err := sd.Finish()
					if err != nil {
						t.Fatal(err)
					}
					return der
				})
				doc, err := pdfsign.Open(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				result := doc.Verify().TrustedRoots(pki.RootPool()).ValidateTimestampCertificates(true)
				if err := result.Err(); err != nil {
					t.Fatal(err)
				}
				sigs := result.Signatures()
				if len(sigs) != 1 {
					t.Fatalf("got %d signatures", len(sigs))
				}
				sig := sigs[0]
				if sig.TimestampValid != tc.trusted {
					t.Errorf("TimestampValid=%v, want %v", sig.TimestampValid, tc.trusted)
				}
				if sig.Timestamp == nil || sig.Timestamp.Certificate == nil || !sig.Timestamp.Certificate.Equal(tc.cert) || sig.Timestamp.Authority != tc.cert.Subject.CommonName {
					t.Error("timestamp identity does not match the actual token signer")
				}
				if !documentTimestamp && !result.Valid() {
					t.Errorf("legitimate PDF signer rejected: %v", sig.Errors)
				}
				if documentTimestamp && tc.cert == untrusted && (result.Valid() || sig.TrustedChain) {
					t.Error("document timestamp borrowed decoy trust")
				}
			})
		}
	}
}

func cmsTestTimestamp(t *testing.T, content []byte, key crypto.Signer, cert *x509.Certificate, decoys []*x509.Certificate) []byte {
	t.Helper()
	return cmsTestTimestampAt(t, content, key, cert, decoys, time.Now().UTC())
}

func cmsTestTimestampAt(t *testing.T, content []byte, key crypto.Signer, cert *x509.Certificate, decoys []*x509.Certificate, at time.Time) []byte {
	t.Helper()
	h := crypto.SHA256.New()
	h.Write(content)
	ts := &timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: h.Sum(nil), Time: at,
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, SerialNumber: big.NewInt(1), AddTSACertificate: true,
	}
	response, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(parsed.RawToken)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	sd.SetContentType(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4})
	for _, decoy := range decoys {
		sd.AddCertificate(decoy)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerify_CMSRevocationUsesSignerChain(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	issuer, issuerKey := pki.IntermediateCerts[0], pki.IntermediateKeys[0]
	_, decoy := cmsTestCertificate(t, "Unrelated revoked certificate", 100, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	key, cert := cmsTestCertificate(t, "Actual signer", 110, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	for _, revoked := range []*x509.Certificate{decoy, cert, issuer} {
		t.Run(revoked.Subject.CommonName, func(t *testing.T) {
			crlIssuer, crlKey := issuer, issuerKey
			if revoked == issuer {
				crlIssuer, crlKey = pki.RootCert, pki.RootKey
			}
			crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: revoked.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}},
			}, crlIssuer, crlKey)
			if err != nil {
				t.Fatal(err)
			}
			data := cmsTestPDF(t, func(content []byte) []byte {
				sd, err := pkcs7.NewSignedData(content)
				if err != nil {
					t.Fatal(err)
				}
				sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
				sd.AddCertificate(decoy)
				for _, c := range pki.Chain() {
					sd.AddCertificate(c)
				}
				if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8},
					Value: revocation.InfoArchival{CRL: revocation.CRL{{FullBytes: crl}}},
				}}}); err != nil {
					t.Fatal(err)
				}
				sd.Detach()
				der, err := sd.Finish()
				if err != nil {
					t.Fatal(err)
				}
				return der
			})
			doc, err := pdfsign.Open(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			result := doc.Verify().TrustedRoots(pki.RootPool())
			wantRevoked := revoked != decoy
			if result.Valid() == wantRevoked {
				t.Errorf("Valid=%v, want %v", result.Valid(), !wantRevoked)
			}
			sigs := result.Signatures()
			if len(sigs) != 1 || sigs[0].Revoked != wantRevoked {
				t.Fatalf("revocation result does not reflect signer chain: %+v", sigs)
			}
		})
	}
}

func cmsTestCertificate(t *testing.T, name string, serial int64, issuer *x509.Certificate, issuerKey crypto.Signer, ku x509.KeyUsage, eku x509.ExtKeyUsage) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: ku, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// Assemble the PDF and ByteRange before signing, without pdfsign's signer
// normalizing the attacker-controlled CMS certificate bag.
func cmsTestPDF(t *testing.T, sign func([]byte) []byte) []byte {
	t.Helper()
	return cmsTestPDFWithSubFilter(t, "adbe.pkcs7.detached", sign)
}

func cmsTestPDFWithSubFilter(t *testing.T, subFilter string, sign func([]byte) []byte) []byte {
	t.Helper()
	const brPlaceholder = "0000000000 0000000000 0000000000 0000000000"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
		"<< /SigFlags 3 /Fields [5 0 R] >>",
		"<< /FT /Sig /T (Signature) /V 6 0 R >>",
		"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /" + subFilter + " /ByteRange [" + brPlaceholder + "] /Contents <" + strings.Repeat("0", 32768) + "> >>",
	}
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	data := buf.Bytes()
	start := bytes.Index(data, []byte("/Contents <")) + len("/Contents ")
	end := start + 32768 + 2
	br := bytes.Index(data, []byte(brPlaceholder))
	copy(data[br:], fmt.Sprintf("%010d %010d %010d %010d", 0, start, end, len(data)-end))
	content := append(append([]byte{}, data[:start]...), data[end:]...)
	der := sign(content)
	if hex.EncodedLen(len(der)) > end-start-2 {
		t.Fatal("CMS signature exceeds placeholder")
	}
	hex.Encode(data[start+1:], der)
	return data
}
