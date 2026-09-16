package revocation

import (
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/ocsp"
)

// InfoArchival is the pkcs7 container containing the revocation information for
// all embedded certificates.
//
// Currently the internal structure is exposed but I don't like to expose the
// asn1.RawValue objects. We can probably make them private and expose the
// information with functions.
type InfoArchival struct {
	CRL   CRL   `asn1:"tag:0,optional,explicit"`
	OCSP  OCSP  `asn1:"tag:1,optional,explicit"`
	Other Other `asn1:"tag:2,optional,explicit"`
}

// AddCRL is used to embed an CRL to revocation.InfoArchival object. You directly
// pass the bytes of a downloaded CRL to this function.
func (r *InfoArchival) AddCRL(b []byte) error {
	r.CRL = append(r.CRL, asn1.RawValue{FullBytes: b})
	return nil
}

// AddOCSP is used to embed the raw bytes of an OCSP response.
func (r *InfoArchival) AddOCSP(b []byte) error {
	r.OCSP = append(r.OCSP, asn1.RawValue{FullBytes: b})
	return nil
}

// IsRevoked reports whether the certificate c has been revoked according to
// the embedded revocation data (CRL and/or OCSP responses).
//
// CRL entries are checked by serial number. OCSP responses are parsed and
// checked individually; responses that cannot be parsed are skipped.
//
// IsRevoked only inspects data already embedded in the InfoArchival. When no
// revocation data is present for a certificate, the function returns false and
// callers should perform an external lookup (e.g., via the verify package's
// EnableExternalRevocationCheck option) to satisfy LTV requirements.
func (r *InfoArchival) IsRevoked(c *x509.Certificate) bool {
	// Check CRLs
	for _, crlRaw := range r.CRL {
		crl, err := x509.ParseRevocationList(crlRaw.FullBytes)
		if err != nil {
			continue
		}
		for _, rc := range crl.RevokedCertificateEntries {
			if rc.SerialNumber.Cmp(c.SerialNumber) == 0 {
				return true
			}
		}
	}

	// Check OCSP responses
	for _, ocspRaw := range r.OCSP {
		// Parse without verifying the responder certificate so that we can
		// inspect the status even when the issuer is not available here.
		resp, err := ocsp.ParseResponse(ocspRaw.FullBytes, nil)
		if err != nil {
			continue
		}
		if resp.SerialNumber != nil && resp.SerialNumber.Cmp(c.SerialNumber) == 0 {
			return resp.Status == ocsp.Revoked
		}
	}

	return false
}

// CRL contains the raw bytes of a pkix.CertificateList and can be parsed with
// x509.PParseCRL.
type CRL []asn1.RawValue

// OCSP contains the raw bytes of an OCSP response and can be parsed with
// x/crypto/ocsp.ParseResponse.
type OCSP []asn1.RawValue

// ANS.1 Object OtherRevInfo.
type Other struct {
	Type  asn1.ObjectIdentifier
	Value []byte
}
