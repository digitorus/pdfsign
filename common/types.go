package common

import (
	"crypto/x509"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

// DocumentInfo contains document information that can be extracted from any PDF.
// This is moved from verify package since it represents generic PDF metadata.
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

// SignatureInfo contains information about the signer and signature.
// This consolidates the duplicated SignatureInfo types from both packages.
type SignatureInfo struct {
	Name          string               `json:"name"`
	Reason        string               `json:"reason"`
	Location      string               `json:"location"`
	ContactInfo   string               `json:"contact_info"`
	SignatureTime *time.Time           `json:"signature_time,omitempty"`
	TimeStamp     *timestamp.Timestamp `json:"time_stamp,omitempty"`
	DocumentHash  string               `json:"document_hash"`
	SignatureHash string               `json:"signature_hash"`
	HashAlgorithm string               `json:"hash_algorithm"`
}

// Certificate contains certificate information and validation results.
// This is moved from verify package but could be useful for signing operations too.
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
