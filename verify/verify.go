package verify

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/pdf"
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

	// AllowNonRepudiationKU allows the Non-Repudiation bit in Key Usage (optional but recommended)
	AllowNonRepudiationKU bool

	// UseEmbeddedTimestamp when true, uses the embedded timestamp for certificate validation
	// instead of the current time. This provides more accurate historical validation.
	UseEmbeddedTimestamp bool

	// FallbackToCurrentTime when true, falls back to current time if embedded timestamp
	// is not available or invalid. If false, validation fails when timestamp is required but missing.
	FallbackToCurrentTime bool

	// AllowEmbeddedCertificatesAsRoots when true, allows using embedded certificates as trusted roots
	// WARNING: This makes signatures appear valid even if they're self-signed or from untrusted CAs
	// Only enable this for testing or when you explicitly trust the embedded certificates
	AllowEmbeddedCertificatesAsRoots bool

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

// DefaultVerifyOptions returns the default verification options following RFC 9336
func DefaultVerifyOptions() *VerifyOptions {
	return &VerifyOptions{
		RequiredEKUs: []x509.ExtKeyUsage{
			// Document Signing EKU per RFC 9336
			x509.ExtKeyUsage(36), // 1.3.6.1.5.5.7.3.36 - not defined in standard library yet
		},
		AllowedEKUs: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection, // Common alternative
			x509.ExtKeyUsageClientAuth,      // Another common alternative
		},
		RequireDigitalSignatureKU:        true,             // Require Digital Signature key usage
		AllowNonRepudiationKU:            true,             // Allow Non-Repudiation key usage
		UseEmbeddedTimestamp:             true,             // Use embedded timestamp for accurate historical validation
		FallbackToCurrentTime:            true,             // Fall back to current time if timestamp unavailable
		AllowEmbeddedCertificatesAsRoots: false,            // SECURE DEFAULT: Don't trust embedded certificates as roots
		EnableExternalRevocationCheck:    false,            // SECURE DEFAULT: Don't make external network calls
		HTTPClient:                       nil,              // Use default HTTP client
		HTTPTimeout:                      10 * time.Second, // 10 second timeout for external checks
	}
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
	SignatureTime      *time.Time           `json:"signature_time,omitempty"`
}

type Certificate struct {
	Certificate       *x509.Certificate `json:"certificate"`
	VerifyError       string            `json:"verify_error"`
	KeyUsageValid     bool              `json:"key_usage_valid"`
	KeyUsageError     string            `json:"key_usage_error,omitempty"`
	ExtKeyUsageValid  bool              `json:"ext_key_usage_valid"`
	ExtKeyUsageError  string            `json:"ext_key_usage_error,omitempty"`
	OCSPResponse      *ocsp.Response    `json:"ocsp_response"`
	OCSPEmbedded      bool              `json:"ocsp_embedded"`
	OCSPExternal      bool              `json:"ocsp_external"`
	CRLRevoked        time.Time         `json:"crl_revoked"`
	CRLEmbedded       bool              `json:"crl_embedded"`
	CRLExternal       bool              `json:"crl_external"`
	RevocationWarning string            `json:"revocation_warning,omitempty"`
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

func File(file *os.File) (apiResp *Response, err error) {
	return FileWithOptions(file, DefaultVerifyOptions())
}

func FileWithOptions(file *os.File, options *VerifyOptions) (apiResp *Response, err error) {
	finfo, _ := file.Stat()
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	return ReaderWithOptions(file, finfo.Size(), options)
}

func Reader(file io.ReaderAt, size int64) (apiResp *Response, err error) {
	return ReaderWithOptions(file, size, DefaultVerifyOptions())
}

func ReaderWithOptions(file io.ReaderAt, size int64, options *VerifyOptions) (apiResp *Response, err error) {
	var documentInfo DocumentInfo

	defer func() {
		if r := recover(); r != nil {
			apiResp = nil
			err = fmt.Errorf("failed to verify file (%v)", r)
		}
	}()
	apiResp = &Response{}

	rdr, err := pdf.NewReader(file, size)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}

	// Parse document info from the PDF Info dictionary
	info := rdr.Trailer().Key("Info")
	if !info.IsNull() {
		parseDocumentInfo(info, &documentInfo)
	}

	// Get page count from the document catalog
	pages := rdr.Trailer().Key("Root").Key("Pages").Key("Count")
	if !pages.IsNull() {
		documentInfo.Pages = int(pages.Int64())
	}

	// AcroForm will contain a SigFlags value if the form contains a digital signature
	t := rdr.Trailer().Key("Root").Key("AcroForm").Key("SigFlags")
	if t.IsNull() {
		return nil, fmt.Errorf("no digital signature in document")
	}

	// Walk over the cross references in the document
	for _, x := range rdr.Xref() {
		// Get the xref object Value
		v := rdr.Resolve(x.Ptr(), x.Ptr())

		// We must have a Filter Adobe.PPKLite
		if v.Key("Filter").Name() != "Adobe.PPKLite" {
			continue
		}

		// Use the new modular signature processing function
		signer, errorMsg, err := processSignature(v, file, options)
		if err != nil {
			// Skip this signature if there's a critical error
			continue
		}

		// Set any error message if present
		if errorMsg != "" && apiResp.Error == "" {
			apiResp.Error = errorMsg
		}

		apiResp.Signers = append(apiResp.Signers, signer)
	}

	if apiResp == nil {
		err = fmt.Errorf("document looks to have a signature but got no results")
	}

	apiResp.DocumentInfo = documentInfo

	return
}
