package verify

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

// buildCertificateChainsWithOptions builds certificate chains with custom verification options
func buildCertificateChainsWithOptions(p7 *pkcs7.PKCS7, signer *Signer, revInfo revocation.InfoArchival, options *VerifyOptions) (string, error) {
	// Directory of certificates, including OCSP
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Determine the verification time and set up time tracking fields
	var verificationTime *time.Time

	// Initialize time tracking fields
	signer.TimeSource = "current_time"
	signer.TimeWarnings = []string{}
	signer.TimestampStatus = "missing"
	signer.TimestampTrusted = false

	// Always prioritize embedded timestamp if present
	if signer.TimeStamp != nil && !signer.TimeStamp.Time.IsZero() {
		verificationTime = &signer.TimeStamp.Time
		signer.TimeSource = "embedded_timestamp"
		signer.TimestampStatus = "valid"

		// Validate timestamp certificate if enabled
		if options.ValidateTimestampCertificates {
			timestampTrusted, timestampWarning := validateTimestampCertificate(signer.TimeStamp, options)
			signer.TimestampTrusted = timestampTrusted
			if timestampWarning != "" {
				signer.TimeWarnings = append(signer.TimeWarnings, timestampWarning)
			}
		}
	} else if options.TrustSignatureTime && signer.SignatureTime != nil {
		// Use signature time as fallback with warning about its untrusted nature
		verificationTime = signer.SignatureTime
		signer.TimeSource = "signature_time"
		signer.TimeWarnings = append(signer.TimeWarnings,
			"Using signature time as fallback - this time is provided by the signatory and should be considered untrusted")
	}
	// If verificationTime is nil, x509.Verify will use current time (default behavior)

	// Set the verification time used
	if verificationTime != nil {
		signer.VerificationTime = verificationTime
	} else {
		currentTime := time.Now()
		signer.VerificationTime = &currentTime
	}

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
	crlStatus := make(map[string]*time.Time) // map[serial]revocationTime (nil means not revoked)
	var crlParseErrors []string
	for _, c := range revInfo.CRL {
		crl, err := x509.ParseRevocationList(c.FullBytes)
		if err != nil {
			crlParseErrors = append(crlParseErrors, fmt.Sprintf("Failed to parse CRL: %v", err))
			continue
		}

		// Check all revoked certificates in this CRL
		for _, revokedCert := range crl.RevokedCertificateEntries {
			serialStr := fmt.Sprintf("%x", revokedCert.SerialNumber)
			crlStatus[serialStr] = &revokedCert.RevocationTime
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
			if options.AllowUntrustedRoots {
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
				c.RevocationTime = &resp.RevokedAt
				// Check if revocation occurred before signing
				revokedBeforeSigning := isRevokedBeforeSigning(resp.RevokedAt, signer.VerificationTime, signer.TimeSource)
				c.RevokedBeforeSigning = revokedBeforeSigning

				if revokedBeforeSigning {
					signer.RevokedCertificate = true
				} else {
					// Add warning that certificate was revoked after signing
					if signer.TimeSource == "embedded_timestamp" {
						signer.TimeWarnings = append(signer.TimeWarnings,
							fmt.Sprintf("Certificate was revoked after signing time (revoked: %v, signed: %v)",
								resp.RevokedAt, signer.VerificationTime))
					} else {
						// Without trusted timestamp, we must assume revocation invalidates signature
						signer.RevokedCertificate = true
						signer.TimeWarnings = append(signer.TimeWarnings,
							"Certificate revoked, but cannot determine if revocation occurred before or after signing without trusted timestamp")
					}
				}
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
		if revocationTime, ok := crlStatus[serialStr]; ok && revocationTime != nil {
			c.CRLEmbedded = true
			c.RevocationTime = revocationTime

			// Check if revocation occurred before signing
			revokedBeforeSigning := isRevokedBeforeSigning(*revocationTime, signer.VerificationTime, signer.TimeSource)
			c.RevokedBeforeSigning = revokedBeforeSigning

			if revokedBeforeSigning {
				signer.RevokedCertificate = true
			} else {
				// Add warning that certificate was revoked after signing
				if signer.TimeSource == "embedded_timestamp" {
					signer.TimeWarnings = append(signer.TimeWarnings,
						fmt.Sprintf("Certificate was revoked after signing time (revoked: %v, signed: %v)",
							revocationTime, signer.VerificationTime))
				} else {
					// Without trusted timestamp, we must assume revocation invalidates signature
					signer.RevokedCertificate = true
					signer.TimeWarnings = append(signer.TimeWarnings,
						"Certificate revoked, but cannot determine if revocation occurred before or after signing without trusted timestamp")
				}
			}
		} else if len(revInfo.CRL) > 0 {
			// CRL is embedded but this certificate is not in it (so it's not revoked via CRL)
			c.CRLEmbedded = true
		}

		// Perform external revocation checks if enabled
		if options.EnableExternalRevocationCheck {
			// External OCSP check
			if !c.OCSPEmbedded && len(cert.OCSPServer) > 0 && len(chain) > 0 && len(chain[0]) > 1 {
				issuer := chain[0][1]
				if externalOCSPResp, err := performExternalOCSPCheck(cert, issuer, options); err == nil {
					c.OCSPResponse = externalOCSPResp
					c.OCSPExternal = true

					if externalOCSPResp.Status != ocsp.Good {
						c.RevocationTime = &externalOCSPResp.RevokedAt
						// Check if revocation occurred before signing
						revokedBeforeSigning := isRevokedBeforeSigning(externalOCSPResp.RevokedAt, signer.VerificationTime, signer.TimeSource)
						c.RevokedBeforeSigning = revokedBeforeSigning

						if revokedBeforeSigning {
							signer.RevokedCertificate = true
						} else {
							// Add warning that certificate was revoked after signing
							if signer.TimeSource == "embedded_timestamp" {
								signer.TimeWarnings = append(signer.TimeWarnings,
									fmt.Sprintf("Certificate was revoked after signing time (external OCSP - revoked: %v, signed: %v)",
										externalOCSPResp.RevokedAt, signer.VerificationTime))
							} else {
								// Without trusted timestamp, we must assume revocation invalidates signature
								signer.RevokedCertificate = true
								signer.TimeWarnings = append(signer.TimeWarnings,
									"Certificate revoked (external OCSP), but cannot determine if revocation occurred before or after signing without trusted timestamp")
							}
						}
					}
				}
			}

			// External CRL check
			if !c.CRLEmbedded && len(cert.CRLDistributionPoints) > 0 {
				if revocationTime, isRevoked, err := performExternalCRLCheck(cert, options); err == nil {
					c.CRLExternal = true
					if isRevoked {
						c.RevocationTime = revocationTime
						// Check if revocation occurred before signing
						revokedBeforeSigning := isRevokedBeforeSigning(*revocationTime, signer.VerificationTime, signer.TimeSource)
						c.RevokedBeforeSigning = revokedBeforeSigning

						if revokedBeforeSigning {
							signer.RevokedCertificate = true
						} else {
							// Add warning that certificate was revoked after signing
							if signer.TimeSource == "embedded_timestamp" {
								signer.TimeWarnings = append(signer.TimeWarnings,
									fmt.Sprintf("Certificate was revoked after signing time (external CRL - revoked: %v, signed: %v)",
										revocationTime, signer.VerificationTime))
							} else {
								// Without trusted timestamp, we must assume revocation invalidates signature
								signer.RevokedCertificate = true
								signer.TimeWarnings = append(signer.TimeWarnings,
									"Certificate revoked (external CRL), but cannot determine if revocation occurred before or after signing without trusted timestamp")
							}
						}
					}
				}
			}
		}

		// Generate revocation warnings
		hasOCSP := c.OCSPEmbedded || c.OCSPExternal
		hasCRL := c.CRLEmbedded || c.CRLExternal
		hasRevocationInfo := hasOCSP || hasCRL

		// Check if certificate has revocation distribution points
		hasOCSPUrl := len(cert.OCSPServer) > 0
		hasCRLUrl := len(cert.CRLDistributionPoints) > 0
		canCheckExternally := hasOCSPUrl || hasCRLUrl

		if !hasRevocationInfo {
			if canCheckExternally {
				if options.EnableExternalRevocationCheck {
					c.RevocationWarning = "External revocation checking enabled but failed to retrieve status from distribution points."
				} else {
					c.RevocationWarning = "No embedded revocation status found. Certificate has distribution points but external checking is not enabled."
				}
			} else {
				c.RevocationWarning = "No revocation status available. Certificate has no embedded OCSP/CRL and no distribution points for external checking."
			}
		} else if !hasOCSP && hasOCSPUrl {
			if options.EnableExternalRevocationCheck {
				c.RevocationWarning = "No OCSP response found despite external checking being enabled."
			} else {
				c.RevocationWarning = "No embedded OCSP response found, but certificate has OCSP URL for external checking."
			}
		} else if !hasCRL && hasCRLUrl {
			warningMsg := ""
			if options.EnableExternalRevocationCheck {
				warningMsg = "No CRL status found despite external checking being enabled."
			} else {
				warningMsg = "No embedded CRL found, but certificate has CRL distribution points for external checking."
			}

			if c.RevocationWarning != "" {
				c.RevocationWarning += " " + warningMsg
			} else {
				c.RevocationWarning = warningMsg
			}
		}

		// Add certificate to result
		signer.Certificates = append(signer.Certificates, c)
	}

	// Set trusted issuer flag based on whether any certificate was verified against system roots
	signer.TrustedIssuer = trustedIssuer

	return errorMsg, nil
}

// validateTimestampCertificate validates the timestamp token's signing certificate
func validateTimestampCertificate(ts *timestamp.Timestamp, options *VerifyOptions) (bool, string) {
	if ts == nil {
		return false, "No timestamp to validate"
	}

	// Parse the timestamp token to get the PKCS7 structure
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return false, fmt.Sprintf("Failed to parse timestamp token: %v", err)
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
		return false, "No timestamp signing certificate found"
	}

	// Verify the timestamp certificate chain against system trusted roots
	opts := x509.VerifyOptions{
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
				return false, fmt.Sprintf("Timestamp certificate chain validation failed: %v", err)
			}
			return true, "Timestamp certificate validated using embedded certificates (not system trusted)"
		}
		return false, fmt.Sprintf("Timestamp certificate chain validation failed: %v", err)
	}

	return true, ""
}

// isRevokedBeforeSigning determines if a certificate was revoked before the signing time
func isRevokedBeforeSigning(revocationTime time.Time, signingTime *time.Time, timeSource string) bool {
	// If we don't have a reliable signing time, we must assume revocation invalidates the signature
	if signingTime == nil || timeSource == "current_time" {
		return true
	}

	// If we only have signature time (untrusted), we should be conservative
	if timeSource == "signature_time" {
		return true
	}

	// For embedded timestamps (trusted), we can make a proper determination
	if timeSource == "embedded_timestamp" {
		return revocationTime.Before(*signingTime)
	}

	// Default to conservative behavior
	return true
}
