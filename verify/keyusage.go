package verify

import (
	"crypto/x509"
	"encoding/asn1"
)

// documentSigningEKUOID is the Document Signing EKU (1.3.6.1.5.5.7.3.36,
// RFC 9336). Go's x509 package has no named ExtKeyUsage constant for it, so
// a certificate carrying it parses the OID into Certificate.
// UnknownExtKeyUsage rather than Certificate.ExtKeyUsage.
var documentSigningEKUOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// documentSigningEKU is a sentinel value used in RequiredEKUs/AllowedEKUs
// lists (e.g. DefaultVerifyOptions, getVerificationEKUs) to stand in for the
// Document Signing OID, since no real certificate can ever have this value
// in its parsed ExtKeyUsage slice - certHasEKU resolves it against
// UnknownExtKeyUsage instead.
const documentSigningEKU = x509.ExtKeyUsage(36)

// certHasEKU reports whether cert carries the given Extended Key Usage,
// resolving the Document Signing sentinel against UnknownExtKeyUsage since
// Go cannot parse that OID into the named ExtKeyUsage slice.
func certHasEKU(cert *x509.Certificate, eku x509.ExtKeyUsage) bool {
	if eku == documentSigningEKU {
		for _, oid := range cert.UnknownExtKeyUsage {
			if oid.Equal(documentSigningEKUOID) {
				return true
			}
		}
		return false
	}
	for _, certEKU := range cert.ExtKeyUsage {
		if certEKU == eku {
			return true
		}
	}
	return false
}

// validateKeyUsage validates certificate Key Usage and Extended Key Usage for PDF signing
// according to RFC 9336 and common industry practices
func validateKeyUsage(cert *x509.Certificate, options *VerifyOptions) (kuValid bool, kuError string, ekuValid bool, ekuError string) {
	// Validate Key Usage - start with valid assumption
	kuValid = true

	// Check Digital Signature bit in Key Usage
	if options.RequireDigitalSignatureKU && (cert.KeyUsage&x509.KeyUsageDigitalSignature) == 0 {
		kuValid = false
		kuError = "certificate does not have Digital Signature key usage"
	}

	// Check for Non-Repudiation (Content Commitment) if required
	if options.RequireNonRepudiation && (cert.KeyUsage&x509.KeyUsageContentCommitment) == 0 {
		kuValid = false
		if kuError != "" {
			kuError += "; certificate does not have Non-Repudiation key usage"
		} else {
			kuError = "certificate does not have Non-Repudiation key usage"
		}
	}

	// Validate Extended Key Usage
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		ekuValid = false
		ekuError = "certificate has no Extended Key Usage extension"
		return
	}

	// Check if any required EKUs are present
	hasRequiredEKU := false
	for _, requiredEKU := range options.RequiredEKUs {
		if certHasEKU(cert, requiredEKU) {
			hasRequiredEKU = true
			break
		}
	}

	// Check if any allowed EKUs are present (fallback)
	hasAllowedEKU := false
	for _, allowedEKU := range options.AllowedEKUs {
		if certHasEKU(cert, allowedEKU) {
			hasAllowedEKU = true
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
	} else {
		// No suitable EKU found
		ekuValid = false
		ekuError = "certificate does not have suitable Extended Key Usage for PDF signing"
	}

	return
}

// getVerificationEKUs returns the appropriate Extended Key Usages for certificate verification
// Includes Document Signing EKU and common alternatives (ExtKeyUsageAny removed as it makes others redundant)
func getVerificationEKUs() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{
		documentSigningEKU,              // Document Signing EKU (1.3.6.1.5.5.7.3.36) per RFC 9336
		x509.ExtKeyUsageEmailProtection, // Email Protection (1.3.6.1.5.5.7.3.4) - common alternative
		x509.ExtKeyUsageClientAuth,      // Client Authentication (1.3.6.1.5.5.7.3.2) - another alternative
	}
}
