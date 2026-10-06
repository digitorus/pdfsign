package pdfsign_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"
	"github.com/digitorus/pkcs7"
)

func TestVerify_TimestampMustBeTrustedForHistoricalValidation(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	issuer, issuerKey := pki.IntermediateCerts[0], pki.IntermediateKeys[0]
	now := time.Now().UTC().Truncate(time.Second)
	stampTime := now.Add(-30 * time.Minute)
	key, liveCert := cmsTestCertificate(t, "Historical signer", 201, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	template := *liveCert
	template.NotAfter = now.Add(-10 * time.Minute)
	der, err := x509.CreateCertificate(rand.Reader, &template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	trustedKey, trustedTSA := cmsTestCertificate(t, "Trusted TSA", 202, issuer, issuerKey, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageTimeStamping)
	untrustedKey, untrustedTSA := cmsTestCertificate(t, "Untrusted TSA", 203, nil, nil, x509.KeyUsageDigitalSignature, x509.ExtKeyUsageTimeStamping)
	for _, revoked := range []bool{false, true} {
		for _, mode := range []string{"untrusted", "trusted", "trusted default", "disabled", "explicit embedded trust"} {
			t.Run(fmt.Sprintf("%s/revoked=%v", mode, revoked), func(t *testing.T) {
				cert := expiredCert
				if revoked {
					cert = liveCert
				}
				tsaKey, tsaCert := trustedKey, trustedTSA
				if mode == "untrusted" || mode == "explicit embedded trust" {
					tsaKey, tsaCert = untrustedKey, untrustedTSA
				}
				data := cmsTestPDF(t, func(content []byte) []byte {
					sd, err := pkcs7.NewSignedData(content)
					if err != nil {
						t.Fatal(err)
					}
					sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
					for _, c := range pki.Chain() {
						sd.AddCertificate(c)
					}
					attrs := []pkcs7.Attribute{{Type: pkcs7.OIDAttributeSigningTime, Value: stampTime}}
					if revoked {
						crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
							Number: big.NewInt(1), ThisUpdate: now.Add(-5 * time.Minute), NextUpdate: now.Add(time.Hour),
							RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: cert.SerialNumber, RevocationTime: now.Add(-10 * time.Minute)}},
						}, issuer, issuerKey)
						if err != nil {
							t.Fatal(err)
						}
						attrs = append(attrs, pkcs7.Attribute{Type: asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, Value: revocation.InfoArchival{CRL: revocation.CRL{{FullBytes: crl}}}})
					}
					if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
						t.Fatal(err)
					}
					si := &sd.GetSignedData().SignerInfos[0]
					token := cmsTestTimestampAt(t, si.EncryptedDigest, tsaKey, tsaCert, pki.Chain(), stampTime)
					if err := si.SetUnauthenticatedAttributes([]pkcs7.Attribute{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}, Value: asn1.RawValue{FullBytes: token}}}); err != nil {
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
				result := doc.Verify().TrustedRoots(pki.RootPool()).TrustSelfSigned(mode == "explicit embedded trust")
				if mode != "trusted default" {
					result.ValidateTimestampCertificates(mode != "disabled")
				}
				wantValid := mode == "trusted" || mode == "trusted default" || mode == "explicit embedded trust"
				if result.Valid() != wantValid || result.Err() != nil {
					t.Errorf("Valid=%v, want %v; error=%v", result.Valid(), wantValid, result.Err())
				}
				sigs := result.Signatures()
				if len(sigs) != 1 || sigs[0].TimestampValid != wantValid {
					t.Fatalf("unexpected timestamp result: %+v", sigs)
				}
				if revoked && !wantValid {
					var revErr *verify.RevocationError
					if !sigs[0].Revoked || !errors.As(errors.Join(sigs[0].Errors...), &revErr) {
						t.Errorf("revocation was suppressed by untrusted time: %+v", sigs[0])
					}
				}
				options := verify.DefaultVerifyOptions() //nolint:staticcheck // Supported legacy API regression.
				options.TrustedRoots = pki.RootPool()
				options.AllowUntrustedRoots = mode == "explicit embedded trust"
				options.ValidateTimestampCertificates = mode != "disabled"
				legacy, err := verify.VerifyWithOptions(bytes.NewReader(data), int64(len(data)), options) //nolint:staticcheck // Supported legacy API regression.
				if err != nil || len(legacy.Signers) != 1 {
					t.Fatalf("legacy verification: %v, %+v", err, legacy)
				}
				signer := legacy.Signers[0]
				if (signer.ValidSignature && len(signer.ValidationErrors) == 0) != wantValid || signer.TimestampTrusted != wantValid {
					t.Errorf("legacy result: %+v", signer)
				}
			})
		}
	}
}

func TestVerify_MalformedByteRangeDoesNotPanic(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	key, cert := cmsTestCertificate(t, "ByteRange signer", 204, pki.IntermediateCerts[0], pki.IntermediateKeys[0], x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	for _, subFilter := range []string{"adbe.pkcs7.detached", "ETSI.RFC3161"} {
		data := cmsTestPDFWithSubFilter(t, subFilter, func(content []byte) []byte {
			sd, err := pkcs7.NewSignedData(content)
			if err != nil {
				t.Fatal(err)
			}
			if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
				t.Fatal(err)
			}
			sd.Detach()
			der, err := sd.Finish()
			if err != nil {
				t.Fatal(err)
			}
			return der
		})
		for _, byteRange := range []string{"[0 10 0 -20]", "[-1 10 0 10]", "[0 0 0 -1]", "[0 0 0 9223372036854775807]", "[0 10 9223372036854775807 10]", "[0 999999 0 10]", "[0 10 0 10]", "[0 1.5 2 1]", "[0 true 2 1]", "[0 10]", "[0 10 0]", "[]"} {
			t.Run(subFilter+byteRange, func(t *testing.T) {
				bad := regexp.MustCompile(`/ByteRange \[[^]]*\]`).ReplaceAllFunc(data, func(original []byte) []byte {
					replacement := "/ByteRange " + byteRange
					if len(replacement) > len(original) {
						t.Fatal("replacement exceeds fixed-width ByteRange")
					}
					return []byte(replacement + strings.Repeat(" ", len(original)-len(replacement)))
				})
				doc, err := pdfsign.Open(bytes.NewReader(bad), int64(len(bad)))
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("verification panic: %v", r)
					}
				}()
				result := doc.Verify().TrustedRoots(pki.RootPool())
				for i := 0; i < 2; i++ {
					if result.Valid() {
						t.Fatal("malformed byte range accepted")
					}
				}
				if result.Err() == nil {
					sigs := result.Signatures()
					if len(sigs) != 1 || len(sigs[0].Errors) == 0 {
						t.Fatalf("missing validation error: %+v", sigs)
					}
				}
				options := verify.DefaultVerifyOptions() //nolint:staticcheck // Supported legacy API regression.
				options.TrustedRoots = pki.RootPool()
				legacy, err := verify.VerifyWithOptions(bytes.NewReader(bad), int64(len(bad)), options) //nolint:staticcheck // Supported legacy API regression.
				if err == nil && (len(legacy.Signers) != 1 || len(legacy.Signers[0].ValidationErrors) == 0 || legacy.Signers[0].ValidSignature) {
					t.Fatalf("legacy accepted malformed byte range: %+v", legacy)
				}
			})
		}
	}
}

type panicAfterOpenReader struct {
	*bytes.Reader
	panicOnRead bool
}

func (r *panicAfterOpenReader) ReadAt(p []byte, off int64) (int, error) {
	if r.panicOnRead {
		panic("test reader failure")
	}
	return r.Reader.ReadAt(p, off)
}

func TestVerify_PanicRecoveryRemainsInvalid(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	key, cert := cmsTestCertificate(t, "Recovery signer", 205, pki.IntermediateCerts[0], pki.IntermediateKeys[0], x509.KeyUsageDigitalSignature, x509.ExtKeyUsageEmailProtection)
	data := cmsTestPDF(t, func(content []byte) []byte {
		sd, err := pkcs7.NewSignedData(content)
		if err != nil {
			t.Fatal(err)
		}
		if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
		sd.Detach()
		der, err := sd.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return der
	})
	rdr := &panicAfterOpenReader{Reader: bytes.NewReader(data)}
	doc, err := pdfsign.Open(rdr, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	rdr.panicOnRead = true
	result := doc.Verify().TrustedRoots(pki.RootPool())
	for i := 0; i < 2; i++ {
		if result.Valid() || result.Err() == nil || len(result.Signatures()) != 0 {
			t.Fatalf("panic recovery exposed a successful or partial result: %+v", result)
		}
	}
}
