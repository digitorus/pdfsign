package verify

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// buildCertificateChains builds certificate chains and verifies revocation status.
func buildCertificateChains(p7 *pkcs7.PKCS7, signer *Signer, revInfo revocation.InfoArchival) (string, error) {
	return buildCertificateChainsWithOptions(p7, signer, revInfo, DefaultVerifyOptions())
}

// buildCertificateChainsWithOptions builds certificate chains with custom verification options
func buildCertificateChainsWithOptions(p7 *pkcs7.PKCS7, signer *Signer, revInfo revocation.InfoArchival, options *VerifyOptions) (string, error) {
	// Directory of certificates, including OCSP
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Determine the verification time based on options and available data
	var verificationTime *time.Time
	if options.UseEmbeddedTimestamp && signer.TimeStamp != nil && !signer.TimeStamp.Time.IsZero() {
		// Use embedded timestamp for historical validation
		verificationTime = &signer.TimeStamp.Time
	} else if signer.SignatureTime != nil {
		// Fall back to signature time if available
		verificationTime = signer.SignatureTime
	} else if options.UseEmbeddedTimestamp && !options.FallbackToCurrentTime {
		// Timestamp required but not available and fallback disabled
		return "Embedded timestamp required but not available in signature", nil
	}
	// If verificationTime is nil, x509.Verify will use current time (default behavior)

	// Parse OCSP response
	ocspStatus := make(map[string]*ocsp.Response)
	var ocspParseErrors []string
	for _, o := range revInfo.OCSP {
		resp, err := ocsp.ParseResponse(o.FullBytes, nil)
		if err != nil {
			// Continue processing other OCSP responses instead of failing entirely
			// We can't get the serial number if parsing failed, so we can't store it
			// But we should track the error for reporting
			ocspParseErrors = append(ocspParseErrors, fmt.Sprintf("Failed to parse OCSP response: %v", err))
			continue
		} else {
			ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = resp
		}
	}

	// Parse CRL responses
	crlStatus := make(map[string]bool) // map[serial]isRevoked
	var crlParseErrors []string
	for _, c := range revInfo.CRL {
		crl, err := x509.ParseRevocationList(c.FullBytes)
		if err != nil {
			crlParseErrors = append(crlParseErrors, fmt.Sprintf("Failed to parse CRL: %v", err))
			continue
		}
		
		// Check all revoked certificates in this CRL
		for _, revokedCert := range crl.RevokedCertificateEntries {
			crlStatus[fmt.Sprintf("%x", revokedCert.SerialNumber)] = true
		}
	}

	// Build certificate chains and verify revocation status
	var errorMsg string
	trustedIssuer := false

	// If we had parsing errors, include them in the error message
	var parseErrors []string
	parseErrors = append(parseErrors, ocspParseErrors...)
	parseErrors = append(parseErrors, crlParseErrors...)
	
	if len(parseErrors) > 0 {
		if len(parseErrors) == 1 {
			errorMsg = parseErrors[0]
		} else {
			errorMsg = fmt.Sprintf("Multiple parsing errors: %v", parseErrors)
		}
	}

	// Get appropriate EKUs for certificate verification
	verificationEKUs := getVerificationEKUs()

	// Helper function to create x509.VerifyOptions with the appropriate time
	createVerifyOptions := func(roots, intermediates *x509.CertPool) x509.VerifyOptions {
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     verificationEKUs,
		}
		if verificationTime != nil {
			opts.CurrentTime = *verificationTime
		}
		return opts
	}

	for _, cert := range p7.Certificates {
		var c Certificate
		c.Certificate = cert

		// Validate Key Usage and Extended Key Usage for PDF signing
		c.KeyUsageValid, c.KeyUsageError, c.ExtKeyUsageValid, c.ExtKeyUsageError = validateKeyUsage(cert, options)

		// Try to verify with system root CAs first
		chain, err := cert.Verify(createVerifyOptions(nil, certPool))

		if err == nil {
			// Successfully verified against system trusted roots
			trustedIssuer = true
		} else {
			// If verification fails with system roots, only try embedded certificates if explicitly allowed
			if options.AllowEmbeddedCertificatesAsRoots {
				altChain, verifyErr := cert.Verify(createVerifyOptions(certPool, certPool))

				// If embedded cert verification fails, record the original system root error
				if verifyErr != nil {
					c.VerifyError = err.Error()
				} else {
					// Successfully verified with embedded certificates (self-signed or private CA)
					chain = altChain
					err = nil
					// Note: trustedIssuer remains false as this wasn't verified against public CAs
				}
			} else {
				// Don't try embedded certificates - record the system root verification error
				c.VerifyError = err.Error()
			}
		}

		if err != nil {
			c.VerifyError = err.Error()
		}

		if resp, ok := ocspStatus[fmt.Sprintf("%x", cert.SerialNumber)]; ok {
			c.OCSPResponse = resp
			c.OCSPEmbedded = true

			if resp.Status != ocsp.Good {
				signer.RevokedCertificate = true
			}

			if len(chain) > 0 && len(chain[0]) > 1 {
				issuer := chain[0][1]
				if resp.Certificate != nil {
					err = resp.Certificate.CheckSignatureFrom(issuer)
					if err != nil {
						errorMsg = fmt.Sprintf("OCSP signing certificate not from certificate issuer: %v", err)
					}
				} else {
					// CA Signed response
					err = resp.CheckSignatureFrom(issuer)
					if err != nil {
						errorMsg = fmt.Sprintf("Failed to verify OCSP response signature: %v", err)
					}
				}
			}
		}

		// Check CRL status
		serialStr := fmt.Sprintf("%x", cert.SerialNumber)
		if isRevoked, ok := crlStatus[serialStr]; ok && isRevoked {
			c.CRLEmbedded = true
			signer.RevokedCertificate = true
		} else if len(revInfo.CRL) > 0 {
			// CRL is embedded but this certificate is not in it (so it's not revoked via CRL)
			c.CRLEmbedded = true
		}

		// Generate revocation warnings
		hasOCSP := c.OCSPEmbedded
		hasCRL := c.CRLEmbedded
		hasRevocationInfo := hasOCSP || hasCRL
		
		// Check if certificate has revocation distribution points
		hasOCSPUrl := len(cert.OCSPServer) > 0
		hasCRLUrl := len(cert.CRLDistributionPoints) > 0
		canCheckExternally := hasOCSPUrl || hasCRLUrl

		if !hasRevocationInfo {
			if canCheckExternally {
				c.RevocationWarning = "No embedded revocation status found. Certificate has distribution points but external checking is not performed."
			} else {
				c.RevocationWarning = "No revocation status available. Certificate has no embedded OCSP/CRL and no distribution points for external checking."
			}
		} else if !hasOCSP && hasOCSPUrl {
			c.RevocationWarning = "No embedded OCSP response found, but certificate has OCSP URL for external checking."
		} else if !hasCRL && hasCRLUrl {
			if c.RevocationWarning != "" {
				c.RevocationWarning += " No embedded CRL found, but certificate has CRL distribution points for external checking."
			} else {
				c.RevocationWarning = "No embedded CRL found, but certificate has CRL distribution points for external checking."
			}
		}

		// Add certificate to result
		signer.Certificates = append(signer.Certificates, c)
	}

	// Set trusted issuer flag based on whether any certificate was verified against system roots
	signer.TrustedIssuer = trustedIssuer

	return errorMsg, nil
}
