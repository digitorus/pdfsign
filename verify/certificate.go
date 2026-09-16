package verify

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

// buildCertificateChainsWithOptions builds certificate chains with custom verification options.
// It returns a validation error (possibly a joined error) that the caller should append to the
// signer's ValidationErrors. This covers an untrusted/unverifiable chain for the leaf (signer)
// certificate, revocation data parse failures, and OCSP/CRL signature issues. None of these stop
// certificate chain building for the remaining certificates.
//
// isDocTimeStamp indicates p7.Certificates[0] is a TSA's own certificate
// (the signature being verified IS a document timestamp) rather than a PDF
// signer's certificate. The RequireDigitalSignatureKU/RequiredEKUs/
// AllowedEKUs policy below is meant for signer certificates and does not
// apply to it - its EKU (id-kp-timeStamping) is instead checked separately
// by validateTimestampCertificate.
func buildCertificateChainsWithOptions(p7 *pkcs7.PKCS7, signer *Signer, revInfo revocation.InfoArchival, options *VerifyOptions, isDocTimeStamp bool) error {
	// PDF signing certificates conventionally carry the Document Signing EKU
	// (1.2.840.113583.1.1.8 / RFC 9336, OID 1.3.6.1.5.5.7.3.36), which Go's
	// x509 package does not recognize as a named ExtKeyUsage constant. Go
	// parses it into Certificate.UnknownExtKeyUsage rather than ExtKeyUsage,
	// and Certificate.Verify's built-in KeyUsages gate only ever matches
	// against the recognized ExtKeyUsage slice: a leaf whose only EKU lives
	// in UnknownExtKeyUsage fails that gate for *any* requested KeyUsages,
	// including ExtKeyUsageAny. So chain-trust verification (is this cert
	// issued by something we trust?) is done here against EKU-stripped
	// clones of every certificate, which sidesteps that gate entirely. EKU
	// *policy* (is this cert allowed to sign PDFs?) is a separate concern,
	// already handled below via validateKeyUsage on the original certs.
	stripped := make([]*x509.Certificate, len(p7.Certificates))
	certPool := x509.NewCertPool()
	for i, cert := range p7.Certificates {
		stripped[i] = stripEKUForChainTrust(cert)
		certPool.AddCert(stripped[i])
	}

	verificationTime := resolveVerificationTime(signer, options)

	ocspStatus, crlStatus, valErr := parseEmbeddedRevocationData(revInfo)

	trustedIssuer := false

	createVerifyOptions := func(roots, intermediates *x509.CertPool) x509.VerifyOptions {
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}
		if verificationTime != nil {
			opts.CurrentTime = *verificationTime
		}
		return opts
	}

	for i, cert := range p7.Certificates {
		var c Certificate
		c.Certificate = cert

		c.KeyUsageValid, c.KeyUsageError, c.ExtKeyUsageValid, c.ExtKeyUsageError = validateKeyUsage(cert, options)

		var chainBroken bool
		chain, err := stripped[i].Verify(createVerifyOptions(options.TrustedRoots, certPool))
		if err == nil {
			trustedIssuer = true
		} else if options.AllowUntrustedRoots {
			altChain, verifyErr := stripped[i].Verify(createVerifyOptions(certPool, certPool))
			if verifyErr != nil {
				c.VerifyError = err.Error()
				chainBroken = true
			} else {
				chain = altChain
				err = nil
			}
		} else {
			c.VerifyError = err.Error()
			chainBroken = true
		}

		if err != nil {
			c.VerifyError = err.Error()
		}

		// The signer's own (leaf) certificate is always p7.Certificates[0].
		// An untrusted or unverifiable chain for it is a real validation
		// failure, not just informational: without it, Valid() would report
		// true for a signature whose certificate chain trusts nothing.
		if i == 0 && chainBroken {
			chainErr := &ValidationError{Msg: fmt.Sprintf("certificate chain could not be verified: %s", c.VerifyError)}
			if valErr != nil {
				valErr = errors.Join(chainErr, valErr)
			} else {
				valErr = chainErr
			}
		}

		// KeyUsage/ExtKeyUsage policy (RequireDigitalSignatureKU,
		// RequireNonRepudiation, RequiredEKUs/AllowedEKUs) only applies to the
		// signer's own (leaf) certificate: CA certificates conventionally
		// carry KeyUsageCertSign rather than DigitalSignature/
		// ContentCommitment, so applying this check to the whole chain would
		// reject legitimate CAs rather than enforce signer policy.
		if i == 0 && !isDocTimeStamp && (!c.KeyUsageValid || !c.ExtKeyUsageValid) {
			msg := c.KeyUsageError
			if c.ExtKeyUsageError != "" {
				if msg != "" {
					msg += "; " + c.ExtKeyUsageError
				} else {
					msg = c.ExtKeyUsageError
				}
			}
			policyErr := &PolicyError{Msg: msg}
			if valErr != nil {
				valErr = errors.Join(policyErr, valErr)
			} else {
				valErr = policyErr
			}
		}

		// Apply embedded and external revocation status checks
		if applyErr := applyRevocationStatus(cert, chain, ocspStatus, crlStatus, signer, &c, options); applyErr != nil && valErr == nil {
			valErr = applyErr
		}

		signer.Certificates = append(signer.Certificates, c)
	}

	signer.TrustedIssuer = trustedIssuer
	return valErr
}

// stripEKUForChainTrust returns a shallow copy of cert with its Extended Key
// Usage fields cleared. It exists solely to sidestep a Go x509 limitation
// (see the comment in buildCertificateChainsWithOptions): the copy is only
// ever used for the chain-trust cert.Verify() call, never stored or used for
// EKU policy decisions, signature checks, or anything else, so clearing
// these fields cannot weaken any other part of verification.
func stripEKUForChainTrust(cert *x509.Certificate) *x509.Certificate {
	clone := *cert
	clone.ExtKeyUsage = nil
	clone.UnknownExtKeyUsage = nil
	return &clone
}

// resolveVerificationTime determines the time to use for certificate chain
// validation and populates the related Signer fields. It returns a pointer to
// the chosen time, or nil if x509 should use the current wall-clock time.
func resolveVerificationTime(signer *Signer, options *VerifyOptions) *time.Time {
	signer.TimeSource = "current_time"
	signer.Warnings = []error{}
	signer.TimestampStatus = "missing"
	signer.TimestampTrusted = false

	var verificationTime *time.Time

	switch {
	case signer.TimeStamp != nil && !signer.TimeStamp.Time.IsZero():
		t := signer.TimeStamp.Time
		verificationTime = &t
		signer.TimeSource = "embedded_timestamp"
		signer.TimestampStatus = "valid"

		if options.ValidateTimestampCertificates {
			trusted, warning := validateTimestampCertificate(signer.TimeStamp, options)
			signer.TimestampTrusted = trusted
			if warning != nil {
				signer.Warnings = append(signer.Warnings, warning)
			}
		}

	case options.TrustSignatureTime && signer.SignatureTime != nil:
		verificationTime = signer.SignatureTime
		signer.TimeSource = "signature_time"
		signer.Warnings = append(signer.Warnings, &Warning{
			Msg: "Using signature time as fallback - this time is provided by the signatory and should be considered untrusted",
		})

	case !options.AtTime.IsZero():
		t := options.AtTime
		verificationTime = &t
	}

	if verificationTime != nil {
		signer.VerificationTime = verificationTime
	} else {
		now := time.Now()
		signer.VerificationTime = &now
	}

	return verificationTime
}

// parseEmbeddedRevocationData parses OCSP responses and CRL entries from the
// embedded revocation info. Entries that cannot be parsed are skipped and
// recorded in the returned error (which is non-fatal).
func parseEmbeddedRevocationData(revInfo revocation.InfoArchival) (
	ocspStatus map[string]*ocsp.Response,
	crlStatus map[string]*time.Time,
	valErr error,
) {
	ocspStatus = make(map[string]*ocsp.Response)
	crlStatus = make(map[string]*time.Time)

	var parseErrors []string

	for _, o := range revInfo.OCSP {
		resp, err := ocsp.ParseResponse(o.FullBytes, nil)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("Failed to parse OCSP response: %v", err))
			continue
		}
		ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = resp
	}

	for _, c := range revInfo.CRL {
		crl, err := x509.ParseRevocationList(c.FullBytes)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("Failed to parse CRL: %v", err))
			continue
		}
		for _, revokedCert := range crl.RevokedCertificateEntries {
			serialStr := fmt.Sprintf("%x", revokedCert.SerialNumber)
			t := revokedCert.RevocationTime
			crlStatus[serialStr] = &t
		}
	}

	switch len(parseErrors) {
	case 0:
	case 1:
		valErr = &RevocationError{Msg: parseErrors[0]}
	default:
		valErr = &RevocationError{Msg: fmt.Sprintf("Multiple parsing errors: %v", parseErrors)}
	}

	return
}

// applyRevocationStatus checks OCSP and CRL status (embedded and, if enabled,
// external) for a single certificate and updates the Certificate and Signer
// fields accordingly. It returns a non-fatal error if OCSP/CRL signature
// verification fails.
func applyRevocationStatus(
	cert *x509.Certificate,
	chain [][]*x509.Certificate,
	ocspStatus map[string]*ocsp.Response,
	crlStatus map[string]*time.Time,
	signer *Signer,
	c *Certificate,
	options *VerifyOptions,
) error {
	var valErr error
	serialStr := fmt.Sprintf("%x", cert.SerialNumber)

	if options.SkipRevocationCheck {
		c.RevocationWarning = buildRevocationWarning(cert, c, options)
		return nil
	}

	// Embedded OCSP
	if resp, ok := ocspStatus[serialStr]; !options.SkipOCSP && ok {
		c.OCSPResponse = resp
		c.OCSPEmbedded = true

		if resp.Status != ocsp.Good {
			c.RevocationTime = &resp.RevokedAt
			if err := applyRevocationImpact(signer, c, resp.RevokedAt); err != nil {
				valErr = err
			}
		}

		if len(chain) > 0 && len(chain[0]) > 1 {
			issuer := chain[0][1]
			var sigErr error
			if resp.Certificate != nil {
				sigErr = resp.Certificate.CheckSignatureFrom(issuer)
			} else {
				sigErr = resp.CheckSignatureFrom(issuer)
			}
			if sigErr != nil && valErr == nil {
				valErr = &RevocationError{Msg: fmt.Sprintf("Failed to verify OCSP response signature: %v", sigErr)}
			}
		}
	}

	// Embedded CRL
	if revocationTime, ok := crlStatus[serialStr]; !options.SkipCRL && ok && revocationTime != nil {
		c.CRLEmbedded = true
		c.RevocationTime = revocationTime
		if err := applyRevocationImpact(signer, c, *revocationTime); err != nil && valErr == nil {
			valErr = err
		}
	} else if !options.SkipCRL && len(ocspStatus) == 0 && len(crlStatus) > 0 {
		// CRL is embedded but this certificate is not listed (not revoked)
		c.CRLEmbedded = true
	}

	// External checks
	if options.EnableExternalRevocationCheck {
		if !options.SkipOCSP && !c.OCSPEmbedded && len(cert.OCSPServer) > 0 && len(chain) > 0 && len(chain[0]) > 1 {
			issuer := chain[0][1]
			if extResp, warning, err := performExternalOCSPCheck(cert, issuer, options); err == nil {
				c.OCSPResponse = extResp
				c.OCSPExternal = true
				if warning != nil {
					signer.Warnings = append(signer.Warnings, warning)
				}
				if extResp.Status != ocsp.Good {
					c.RevocationTime = &extResp.RevokedAt
					if err := applyRevocationImpact(signer, c, extResp.RevokedAt); err != nil && valErr == nil {
						valErr = err
					}
				}
			}
		}

		if !options.SkipCRL && !c.CRLEmbedded && len(cert.CRLDistributionPoints) > 0 {
			var issuer *x509.Certificate
			if len(chain) > 0 && len(chain[0]) > 1 {
				issuer = chain[0][1]
			}
			if revocationTime, isRevoked, warning, err := performExternalCRLCheckWithIssuer(cert, issuer, options); err == nil {
				c.CRLExternal = true
				if warning != nil {
					signer.Warnings = append(signer.Warnings, warning)
				}
				if isRevoked {
					c.RevocationTime = revocationTime
					if err := applyRevocationImpact(signer, c, *revocationTime); err != nil && valErr == nil {
						valErr = err
					}
				}
			}
		}
	}

	// Generate a human-readable revocation warning
	c.RevocationWarning = buildRevocationWarning(cert, c, options)

	return valErr
}

// applyRevocationImpact updates the signer and certificate revocation fields
// after a revocation event is detected, and returns a non-nil error when the
// revocation should invalidate the signature (signer.RevokedCertificate is
// set to true in that case; the caller must propagate the error into
// signer.ValidationErrors, since RevokedCertificate alone is not otherwise
// consulted when determining whether the signature is valid).
func applyRevocationImpact(signer *Signer, c *Certificate, revocationTime time.Time) error {
	revokedBeforeSigning := signer.IsRevokedBeforeSigning(revocationTime)
	c.RevokedBeforeSigning = revokedBeforeSigning

	if revokedBeforeSigning {
		signer.RevokedCertificate = true
		return &RevocationError{Msg: fmt.Sprintf("certificate was revoked before signing (revoked: %v)", revocationTime)}
	}

	if signer.TimeSource == "embedded_timestamp" {
		signer.Warnings = append(signer.Warnings, &Warning{
			Msg: fmt.Sprintf("Certificate was revoked after signing time (revoked: %v, signed: %v)",
				revocationTime, signer.VerificationTime),
		})
		return nil
	}

	signer.RevokedCertificate = true
	signer.Warnings = append(signer.Warnings, &Warning{
		Msg: "Certificate revoked, but cannot determine if revocation occurred before or after signing without trusted timestamp",
	})
	return &RevocationError{Msg: "certificate is revoked and revocation time relative to signing could not be determined"}
}

// buildRevocationWarning returns a human-readable warning string describing the
// revocation coverage for a certificate, or an empty string if revocation data
// is sufficient.
func buildRevocationWarning(cert *x509.Certificate, c *Certificate, options *VerifyOptions) string {
	hasOCSP := c.OCSPEmbedded || c.OCSPExternal
	hasCRL := c.CRLEmbedded || c.CRLExternal
	hasRevocationInfo := hasOCSP || hasCRL
	hasOCSPURL := len(cert.OCSPServer) > 0
	hasCRLURL := len(cert.CRLDistributionPoints) > 0
	canCheckExternally := hasOCSPURL || hasCRLURL

	if !hasRevocationInfo {
		if canCheckExternally {
			if options.EnableExternalRevocationCheck {
				return "External revocation checking enabled but failed to retrieve status from distribution points."
			}
			return "No embedded revocation status found. Certificate has distribution points but external checking is not enabled."
		}
		return "No revocation status available. Certificate has no embedded OCSP/CRL and no distribution points for external checking."
	}

	var warnings []string
	if !hasOCSP && hasOCSPURL {
		if options.EnableExternalRevocationCheck {
			warnings = append(warnings, "No OCSP response found despite external checking being enabled.")
		} else {
			warnings = append(warnings, "No embedded OCSP response found, but certificate has OCSP URL for external checking.")
		}
	}
	if !hasCRL && hasCRLURL {
		if options.EnableExternalRevocationCheck {
			warnings = append(warnings, "No CRL status found despite external checking being enabled.")
		} else {
			warnings = append(warnings, "No embedded CRL found, but certificate has CRL distribution points for external checking.")
		}
	}

	if len(warnings) > 0 {
		result := warnings[0]
		for _, w := range warnings[1:] {
			result += " " + w
		}
		return result
	}
	return ""
}

// validateTimestampCertificate validates the timestamp token's signing certificate
func validateTimestampCertificate(ts *timestamp.Timestamp, options *VerifyOptions) (bool, error) {
	if ts == nil {
		return false, &Warning{Msg: "No timestamp to validate"}
	}

	// Parse the timestamp token to get the PKCS7 structure
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return false, &Warning{Msg: fmt.Sprintf("Failed to parse timestamp token: %v", err)}
	}

	// Create certificate pool from timestamp certificates
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Find the timestamp signing certificate
	var timestampCert *x509.Certificate
	for _, cert := range p7.Certificates {
		// Look for the certificate that signed the timestamp
		// Usually this will be the first one, but we should verify
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			timestampCert = cert
			break
		}
	}

	if timestampCert == nil {
		return false, &Warning{Msg: "No timestamp signing certificate found"}
	}
	for _, cert := range p7.Certificates {
		isLeaf := cert.Equal(timestampCert)
		if !isLeaf && !options.ValidateFullChain {
			continue
		}
		if err := verifyCertificateAlgorithmAndKeySize(cert, options, isLeaf); err != nil {
			return false, &Warning{Msg: fmt.Sprintf("Timestamp certificate algorithm policy failed: %v", err)}
		}
	}

	// Verify the timestamp certificate chain against system trusted roots
	opts := x509.VerifyOptions{
		Roots:         options.TrustedRoots,
		Intermediates: certPool,
		CurrentTime:   ts.Time, // Use timestamp time for validation
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	_, err = timestampCert.Verify(opts)
	if err != nil {
		// Try with embedded certificates as roots if allowed
		if options.AllowUntrustedRoots {
			opts.Roots = certPool
			_, err = timestampCert.Verify(opts)
			if err != nil {
				return false, &Warning{Msg: fmt.Sprintf("Timestamp certificate chain validation failed: %v", err)}
			}
			return true, &Warning{Msg: "Timestamp certificate validated using embedded certificates (not system trusted)"}
		}
		return false, &Warning{Msg: fmt.Sprintf("Timestamp certificate chain validation failed: %v", err)}
	}

	return true, nil
}

// IsRevokedBeforeSigning determines if a certificate was revoked before the signing time
func (s *Signer) IsRevokedBeforeSigning(revocationTime time.Time) bool {
	// If we don't have a reliable signing time, we must assume revocation invalidates the signature
	if s.VerificationTime == nil || s.TimeSource == "current_time" {
		return true
	}

	// If we only have signature time (untrusted), we should be conservative
	if s.TimeSource == "signature_time" {
		return true
	}

	// For embedded timestamps (trusted), we can make a proper determination
	if s.TimeSource == "embedded_timestamp" {
		return revocationTime.Before(*s.VerificationTime)
	}

	// Default to conservative behavior
	return true
}
