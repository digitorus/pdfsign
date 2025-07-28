package verify

// This file contains type definitions used across the verify package.
// Types are defined in verify.go to maintain backward compatibility.

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/digitorus/pdfsign/common"
)

// VerifyOptions contains options for PDF signature verification
type VerifyOptions struct {
	// RequiredEKUs specifies the Extended Key Usages that must be present
	// Default: Document Signing EKU (1.3.6.1.5.5.7.3.36) per RFC 9336
	RequiredEKUs []x509.ExtKeyUsage

	// AllowedEKUs specifies additional Extended Key Usages that are acceptable
	// Common alternatives: Email Protection (1.3.6.1.5.5.7.3.4), Client Auth (1.3.6.1.5.5.7.3.2)
	AllowedEKUs []x509.ExtKeyUsage

	// RequireDigitalSignatureKU requires the Digital Signature bit in Key Usage
	RequireDigitalSignatureKU bool

	// RequireNonRepudiation requires the Non-Repudiation bit in Key Usage (mandatory for highest security)
	RequireNonRepudiation bool

	// TrustSignatureTime when true, trusts the signature time embedded in the PDF if no timestamp is present
	// WARNING: This time is provided by the signatory and should be considered untrusted for security-critical applications.
	TrustSignatureTime bool

	// ValidateTimestampCertificates when true, validates the timestamp token's signing certificate
	// including building a proper certification path and checking revocation status.
	ValidateTimestampCertificates bool

	// AllowUntrustedRoots when true, allows using certificates embedded in the PDF as trusted roots
	// WARNING: This makes signatures appear valid even if they're self-signed or from untrusted CAs
	// Only enable this for testing or when you explicitly trust the embedded certificates
	AllowUntrustedRoots bool

	// EnableExternalRevocationCheck when true, performs external OCSP and CRL checks
	// using the URLs found in certificate extensions
	EnableExternalRevocationCheck bool

	// HTTPClient specifies the HTTP client to use for external revocation checking
	// If nil, http.DefaultClient will be used
	HTTPClient *http.Client

	// HTTPTimeout specifies the timeout for HTTP requests during external revocation checking
	// If zero, a default timeout of 10 seconds will be used
	HTTPTimeout time.Duration
}

// SignatureValidation contains validation results and technical details
// (not about the signer's intent)
type SignatureValidation struct {
	ValidSignature     bool                 `json:"valid_signature"`
	TrustedIssuer      bool                 `json:"trusted_issuer"`
	RevokedCertificate bool                 `json:"revoked_certificate"`
	Certificates       []common.Certificate `json:"certificates"`
	TimestampStatus    string               `json:"timestamp_status,omitempty"`
	TimestampTrusted   bool                 `json:"timestamp_trusted"`
	VerificationTime   *time.Time           `json:"verification_time"`
	TimeSource         string               `json:"time_source"`
	TimeWarnings       []string             `json:"time_warnings,omitempty"`
}

type Response struct {
	Error string

	DocumentInfo common.DocumentInfo
	Signatures   []struct {
		Info       common.SignatureInfo `json:"info"`
		Validation SignatureValidation  `json:"validation"`
	}
}
