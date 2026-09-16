package verify

// This file contains type definitions used across the verify package.
// Types are defined in verify.go to maintain backward compatibility.

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

const (
	// DefaultMaxOCSPResponseBytes is the default value of
	// VerifyOptions.MaxOCSPResponseBytes when unset. Classical (RSA/ECDSA)
	// OCSP responses are a few KB; post-quantum signature algorithms (e.g.
	// ML-DSA, SLH-DSA) produce substantially larger signatures and
	// certificates, so this leaves generous headroom for both.
	DefaultMaxOCSPResponseBytes int64 = 4 << 20 // 4 MiB

	// DefaultMaxCRLResponseBytes is the default value of
	// VerifyOptions.MaxCRLResponseBytes when unset. Large enterprise CRLs
	// with many entries, or ones signed with a post-quantum algorithm, can
	// run well into the tens of MB; this leaves generous headroom.
	DefaultMaxCRLResponseBytes int64 = 256 << 20 // 256 MiB
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

	// TrustedRoots, if non-nil, is the pool of root certificates used to verify the
	// signer's certificate chain, instead of the system root pool. Checked before
	// falling back to AllowUntrustedRoots.
	TrustedRoots *x509.CertPool

	// SkipRevocationCheck disables all revocation checking (OCSP and CRL,
	// embedded and external). Takes precedence over SkipOCSP/SkipCRL.
	SkipRevocationCheck bool

	// SkipOCSP disables OCSP data (embedded or externally fetched) as a
	// revocation source.
	SkipOCSP bool

	// SkipCRL disables CRL data (embedded or externally fetched) as a
	// revocation source.
	SkipCRL bool

	// EnableExternalRevocationCheck when true, performs external OCSP and CRL checks
	// using the URLs found in certificate extensions
	EnableExternalRevocationCheck bool

	// ValidateFullChain when true, enforces cryptographic policy constraints (Min...KeySize, AllowedAlgorithms)
	// on the entire certificate chain.
	//
	// Note: Standard x509 verification and revocation checking (OCSP/CRL) are ALWAYS performed on the
	// entire chain regardless of this setting. This setting strictly controls whether the specific
	// cryptographic strength policies set in this options struct are applied to intermediate and root CAs.
	ValidateFullChain bool

	// HTTPClient specifies the HTTP client to use for external revocation checking
	// If nil, http.DefaultClient will be used
	HTTPClient *http.Client

	// HTTPTimeout specifies the timeout for HTTP requests during external revocation checking
	// If zero, a default timeout of 10 seconds will be used
	HTTPTimeout time.Duration

	// MaxOCSPResponseBytes bounds how much of an external OCSP response body
	// is buffered into memory, protecting against a malicious or
	// misbehaving responder streaming an unbounded body. If zero,
	// DefaultMaxOCSPResponseBytes is used.
	MaxOCSPResponseBytes int64

	// MaxCRLResponseBytes bounds how much of an external CRL response body
	// is buffered into memory, protecting against a malicious or
	// misbehaving responder streaming an unbounded body. If zero,
	// DefaultMaxCRLResponseBytes is used.
	MaxCRLResponseBytes int64

	// MinRSAKeySize constrains the minimum bit size for RSA keys (e.g. 2048, 4096)
	MinRSAKeySize int

	// MinECDSAKeySize constrains the minimum curve size for ECDSA keys (e.g. 256, 384)
	MinECDSAKeySize int

	// AllowedAlgorithms restricts the permitted public key algorithms (e.g. x509.RSA, x509.ECDSA)
	// If empty, all algorithms are allowed.
	AllowedAlgorithms []x509.PublicKeyAlgorithm

	// AtTime controls the time used for certificate validation.
	// If zero, the current time is used.
	AtTime time.Time

	// Context bounds external OCSP/CRL requests. If nil, context.Background()
	// is used, so those requests are governed only by HTTPTimeout (or its
	// 10-second default). Cancelling Context aborts an in-flight request
	// immediately, independent of HTTPTimeout.
	Context context.Context
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
	Warnings           []error              `json:"warnings,omitempty"`         // Non-fatal warnings encountered during verification
	ValidationErrors   []error              `json:"-"`                          // Validation errors encountered
}

// NewSigner creates a new Signer with default values.
func NewSigner() *Signer {
	return &Signer{
		Warnings: []error{},
	}
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
