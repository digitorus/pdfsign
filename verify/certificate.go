package verify

import (
	"crypto/x509"
	"fmt"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// buildCertificateChains builds certificate chains and verifies revocation status.
func buildCertificateChains(p7 *pkcs7.PKCS7, signer *Signer, revInfo revocation.InfoArchival) (string, error) {
	// Directory of certificates, including OCSP
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Parse OCSP response
	ocspStatus := make(map[string]*ocsp.Response)
	for _, o := range revInfo.OCSP {
		resp, err := ocsp.ParseResponse(o.FullBytes, nil)
		if err != nil {
			ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = nil
			return fmt.Sprintf("Failed to parse or verify OCSP response: %v", err), nil
		} else {
			ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = resp
		}
	}

	// Build certificate chains and verify revocation status
	var errorMsg string
	trustedIssuer := false

	for _, cert := range p7.Certificates {
		var c Certificate
		c.Certificate = cert

		// Try to verify with system root CAs first
		chain, err := cert.Verify(x509.VerifyOptions{
			Roots:         nil, // Use system root CAs
			Intermediates: certPool,
			CurrentTime:   cert.NotBefore,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
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
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
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
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
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
