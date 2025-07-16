package verify

import (
	"crypto/x509"
	"fmt"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// validateKeyUsage validates certificate Key Usage and Extended Key Usage for PDF signing
// according to RFC 9336 and common industry practices
func validateKeyUsage(cert *x509.Certificate, options *VerifyOptions) (kuValid bool, kuError string, ekuValid bool, ekuError string) {
	// Validate Key Usage
	kuValid = true
	ekuValid = true
	
	// Check Digital Signature bit in Key Usage
	if options.RequireDigitalSignatureKU && (cert.KeyUsage&x509.KeyUsageDigitalSignature) == 0 {
		kuValid = false
		kuError = "certificate does not have Digital Signature key usage"
	}
	
	// Check for Non-Repudiation (Content Commitment) if present
	// This is optional but recommended for PDF signing
	if options.AllowNonRepudiationKU && (cert.KeyUsage&x509.KeyUsageContentCommitment) != 0 {
		// Non-repudiation is present and allowed - this is good
	}
	
	// Validate Extended Key Usage
	if len(cert.ExtKeyUsage) == 0 {
		ekuValid = false
		ekuError = "certificate has no Extended Key Usage extension"
		return
	}
	
	// Check if any required EKUs are present
	hasRequiredEKU := false
	if len(options.RequiredEKUs) > 0 {
		for _, requiredEKU := range options.RequiredEKUs {
			for _, certEKU := range cert.ExtKeyUsage {
				if certEKU == requiredEKU {
					hasRequiredEKU = true
					break
				}
			}
			if hasRequiredEKU {
				break
			}
		}
	}
	
	// Check if any allowed EKUs are present (fallback)
	hasAllowedEKU := false
	if len(options.AllowedEKUs) > 0 {
		for _, allowedEKU := range options.AllowedEKUs {
			for _, certEKU := range cert.ExtKeyUsage {
				if certEKU == allowedEKU {
					hasAllowedEKU = true
					break
				}
			}
			if hasAllowedEKU {
				break
			}
		}
	}
	
	// Check for ExtKeyUsageAny which is too permissive for PDF signing
	hasAnyEKU := false
	for _, certEKU := range cert.ExtKeyUsage {
		if certEKU == x509.ExtKeyUsageAny {
			hasAnyEKU = true
			break
		}
	}
	
	// Determine EKU validity
	if hasRequiredEKU {
		// Has a required EKU - this is the best case
		ekuValid = true
	} else if hasAllowedEKU {
		// Has an allowed EKU but not a required one
		ekuValid = true
		if len(options.RequiredEKUs) > 0 {
			ekuError = "certificate uses acceptable but not preferred Extended Key Usage"
		}
	} else if hasAnyEKU {
		// Has ExtKeyUsageAny - warn but don't fail for backward compatibility
		ekuValid = true
		ekuError = "certificate uses ExtKeyUsageAny which is too permissive for PDF signing"
	} else {
		// No suitable EKU found
		ekuValid = false
		ekuError = "certificate does not have suitable Extended Key Usage for PDF signing"
	}
	
	return
}

// getVerificationEKUs returns the appropriate Extended Key Usages for certificate verification
// Includes Document Signing EKU and common alternatives
func getVerificationEKUs() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{
		x509.ExtKeyUsage(36),             // Document Signing EKU (1.3.6.1.5.5.7.3.36) per RFC 9336
		x509.ExtKeyUsageEmailProtection,  // Email Protection (1.3.6.1.5.5.7.3.4) - common alternative
		x509.ExtKeyUsageClientAuth,       // Client Authentication (1.3.6.1.5.5.7.3.2) - another alternative
		x509.ExtKeyUsageAny,              // Any EKU - for backward compatibility (less secure)
	}
}

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

	// Build certificate chains and verify revocation status
	var errorMsg string
	trustedIssuer := false

	// If we had OCSP parsing errors, include them in the error message
	if len(ocspParseErrors) > 0 {
		if len(ocspParseErrors) == 1 {
			errorMsg = ocspParseErrors[0]
		} else {
			errorMsg = fmt.Sprintf("Multiple OCSP parsing errors: %v", ocspParseErrors)
		}
	}

	// Get appropriate EKUs for certificate verification
	verificationEKUs := getVerificationEKUs()

	for _, cert := range p7.Certificates {
		var c Certificate
		c.Certificate = cert

		// Validate Key Usage and Extended Key Usage for PDF signing
		c.KeyUsageValid, c.KeyUsageError, c.ExtKeyUsageValid, c.ExtKeyUsageError = validateKeyUsage(cert, options)

		// Try to verify with system root CAs first
		chain, err := cert.Verify(x509.VerifyOptions{
			Roots:         nil, // Use system root CAs
			Intermediates: certPool,
			CurrentTime:   cert.NotBefore,
			KeyUsages:     verificationEKUs, // Use appropriate EKUs for verification
		})

		if err == nil {
			// Successfully verified against system trusted roots
			trustedIssuer = true
		} else {
			// Debug: let's try with current time instead of NotBefore
			chainCurrentTime, errCurrentTime := cert.Verify(x509.VerifyOptions{
				Roots:         nil, // Use system root CAs
				Intermediates: certPool,
				// CurrentTime not specified - uses current time
				KeyUsages: verificationEKUs, // Use appropriate EKUs for verification
			})

			if errCurrentTime == nil {
				// Successfully verified with current time
				chain = chainCurrentTime
				err = nil
				trustedIssuer = true
			} else {
				// If verification fails with system roots, try with embedded certificates as roots
				altChain, verifyErr := cert.Verify(x509.VerifyOptions{
					Roots:         certPool, // Use certificates from the signature as potential roots
					Intermediates: certPool,
					CurrentTime:   cert.NotBefore,
					KeyUsages:     verificationEKUs, // Use appropriate EKUs for verification
				})

				// If embedded cert verification fails, record the original system root error
				if verifyErr != nil {
					c.VerifyError = err.Error()
				} else {
					// Successfully verified with embedded certificates (self-signed or private CA)
					chain = altChain
					err = nil
					// Note: trustedIssuer remains false as this wasn't verified against public CAs
				}
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

		// Add certificate to result
		signer.Certificates = append(signer.Certificates, c)
	}

	// Set trusted issuer flag based on whether any certificate was verified against system roots
	signer.TrustedIssuer = trustedIssuer

	return errorMsg, nil
}
