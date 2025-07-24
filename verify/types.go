package verify

// This file contains type definitions used across the verify package.
// Types are defined in verify.go to maintain backward compatibility.

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
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

type Response struct {
	Error string

	DocumentInfo DocumentInfo
	Signers      []Signer
}

type Signer struct {
	Name               string               `json:"name"`
	Reason             string               `json:"reason"`
	Location           string               `json:"location"`
	ContactInfo        string               `json:"contact_info"`
	ValidSignature     bool                 `json:"valid_signature"`
	TrustedIssuer      bool                 `json:"trusted_issuer"`
	RevokedCertificate bool                 `json:"revoked_certificate"`
	Certificates       []Certificate        `json:"certificates"`
	TimeStamp          *timestamp.Timestamp `json:"time_stamp"`
	SignatureTime      *time.Time           `json:"signature_time,omitempty"`   // Time from the signature object, may be untrusted
	TimestampStatus    string               `json:"timestamp_status,omitempty"` // "valid", "invalid", "missing"
	TimestampTrusted   bool                 `json:"timestamp_trusted"`          // Whether timestamp certificate chain is trusted
	VerificationTime   *time.Time           `json:"verification_time"`          // Time used for certificate validation
	TimeSource         string               `json:"time_source"`                // "embedded_timestamp", "signature_time", "current_time"
	TimeWarnings       []string             `json:"time_warnings,omitempty"`    // Warnings about time validation
}

type Certificate struct {
	Certificate          *x509.Certificate `json:"certificate"`
	VerifyError          string            `json:"verify_error"`
	KeyUsageValid        bool              `json:"key_usage_valid"`
	KeyUsageError        string            `json:"key_usage_error,omitempty"`
	ExtKeyUsageValid     bool              `json:"ext_key_usage_valid"`
	ExtKeyUsageError     string            `json:"ext_key_usage_error,omitempty"`
	OCSPResponse         *ocsp.Response    `json:"ocsp_response"`
	OCSPEmbedded         bool              `json:"ocsp_embedded"`
	OCSPExternal         bool              `json:"ocsp_external"`
	CRLRevoked           time.Time         `json:"crl_revoked"`
	CRLEmbedded          bool              `json:"crl_embedded"`
	CRLExternal          bool              `json:"crl_external"`
	RevocationWarning    string            `json:"revocation_warning,omitempty"`
	RevocationTime       *time.Time        `json:"revocation_time,omitempty"` // When the certificate was revoked (if applicable)
	RevokedBeforeSigning bool              `json:"revoked_before_signing"`    // Whether revocation occurred before signing
}

// DocumentInfo contains document information.
type DocumentInfo struct {
	Author     string `json:"author"`
	Creator    string `json:"creator"`
	Hash       string `json:"hash"`
	Name       string `json:"name"`
	Permission string `json:"permission"`
	Producer   string `json:"producer"`
	Subject    string `json:"subject"`
	Title      string `json:"title"`

	Pages        int       `json:"pages"`
	Keywords     []string  `json:"keywords"`
	ModDate      time.Time `json:"mod_date"`
	CreationDate time.Time `json:"creation_date"`
}
