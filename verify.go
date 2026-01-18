package pdfsign

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/verify"
)

// VerifyOption is a functional option for configuring verification.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	trustedRoots       *x509.CertPool
	trustEmbedded      bool
	checkRevocation    bool
	allowOCSP          bool
	allowCRL           bool
	externalChecks     bool
	validateFullChain  bool
	validationTime     *time.Time
	trustSignatureTime bool
	requireDigSig      bool
	requireNonRepud    bool
	allowedEKUs        []x509.ExtKeyUsage
	minRSAKeySize      int
	minECDSAKeySize    int
	allowedAlgorithms  []x509.PublicKeyAlgorithm
}

// Verify initializes a VerifyBuilder to configure and execute signature verification.
// The verification process is lazy and only executes when you access the results (e.g., via Valid() or Signatures()).
func (d *Document) Verify() *VerifyBuilder {
	return &VerifyBuilder{
		doc:           d,
		allowOCSP:     true,
		allowCRL:      true,
		trustEmbedded: true,
	}
}

// execute performs the actual verification if not already done (lazy execution).
// Results are stored in the builder's internal fields.
func (b *VerifyBuilder) execute() {
	if b.executed {
		return
	}
	b.executed = true

	// Helper to create internal options
	vOpts := &verify.VerifyOptions{
		RequiredEKUs: []x509.ExtKeyUsage{
			x509.ExtKeyUsage(36), // 1.3.6.1.5.5.7.3.36 - not defined in standard library yet
		},
		AllowedEKUs: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageClientAuth,
		},
		RequireDigitalSignatureKU:     true,
		ValidateTimestampCertificates: true,
		HTTPTimeout:                   10 * time.Second,
	}

	vOpts.AllowUntrustedRoots = b.trustEmbedded
	vOpts.EnableExternalRevocationCheck = b.externalChecks
	vOpts.ValidateFullChain = b.validateFullChain
	vOpts.ValidateTimestampCertificates = b.validateTimestampCert

	if b.requireDigSig {
		vOpts.RequireDigitalSignatureKU = true
	}
	if b.requireNonRepud {
		vOpts.RequireNonRepudiation = true
	}
	if b.trustSignatureTime {
		vOpts.TrustSignatureTime = true
	}
	if b.allowedEKUs != nil {
		vOpts.AllowedEKUs = b.allowedEKUs
	}
	if b.minRSAKeySize > 0 {
		vOpts.MinRSAKeySize = b.minRSAKeySize
	}
	if b.minECDSAKeySize > 0 {
		vOpts.MinECDSAKeySize = b.minECDSAKeySize
	}
	if b.allowedAlgorithms != nil {
		vOpts.AllowedAlgorithms = b.allowedAlgorithms
	}
	if b.validationTime != nil {
		vOpts.AtTime = *b.validationTime
	}

	// Initialization validation
	if b.doc.rdr == nil {
		if b.doc.reader == nil {
			b.err = fmt.Errorf("verification failed: document reader is nil")
			return
		}
		var err error
		b.doc.rdr, err = pdf.NewReader(b.doc.reader, b.doc.size)
		if err != nil {
			b.err = fmt.Errorf("verification failed: could not open PDF: %w", err)
			return
		}
	}

	// Parse Document Info
	info := b.doc.rdr.Trailer().Key("Info")
	if !info.IsNull() {
		parseDocumentInfo(info, &b.document)
	}
	pages := b.doc.rdr.Trailer().Key("Root").Key("Pages").Key("Count")
	if !pages.IsNull() {
		b.document.Pages = int(pages.Int64())
	}

	// Iterate Signatures
	count := 0
	for sig, err := range b.doc.Signatures() {
		if err != nil {
			b.err = fmt.Errorf("verification failed: could not iterate signatures: %w", err)
			return
		}
		count++

		// Call internal verify logic
		signer, errorMsg, err := verify.VerifySignature(sig.Object(), b.doc.reader, b.doc.size, vOpts)
		if err != nil {
			// Legacy behavior: skip signatures that can't be processed or verified
			continue
		}

		// Map Signer to SignatureVerifyResult
		sigResult := SignatureVerifyResult{
			SignatureInfo: SignatureInfo{
				SignerName: signer.Name,
				Reason:     signer.Reason,
				Location:   signer.Location,
				Contact:    signer.ContactInfo,
			},
			Valid:          signer.ValidSignature,
			TrustedChain:   signer.TrustedIssuer,
			Revoked:        signer.RevokedCertificate,
			TimestampValid: signer.TimestampTrusted,
			Warnings:       signer.TimeWarnings,
		}

		// Add error message if any
		if errorMsg != "" {
			sigResult.Errors = append(sigResult.Errors, fmt.Errorf("%s", errorMsg))
			sigResult.Valid = false
		}

		if signer.SignatureTime != nil {
			sigResult.SigningTime = *signer.SignatureTime
		}
		if len(signer.Certificates) > 0 {
			sigResult.Certificate = signer.Certificates[0].Certificate
		}

		b.signatures = append(b.signatures, sigResult)
	}

	if count == 0 {
		b.err = fmt.Errorf("verification failed: document appears to have signatures but none could be processed")
	}
}

// Internal helper to parse document info
func parseDocumentInfo(v pdf.Value, info *DocumentInfo) {
	info.Author = v.Key("Author").Text()
	info.Creator = v.Key("Creator").Text()
	info.Title = v.Key("Title").Text()
	info.Subject = v.Key("Subject").Text()
	info.Producer = v.Key("Producer").Text()

	// Parse dates
	if d := v.Key("CreationDate"); !d.IsNull() {
		info.CreationDate, _ = parseDate(d.Text())
	}
	if d := v.Key("ModDate"); !d.IsNull() {
		info.ModDate, _ = parseDate(d.Text())
	}
}

// parseDate parses PDF formatted dates (D:YYYYMMDDHHmmSSOHH'mm')
func parseDate(v string) (time.Time, error) {
	return time.Parse("D:20060102150405Z07'00'", v)
}

// TrustedRoots sets the trusted root certificate pool.
func TrustedRoots(pool *x509.CertPool) VerifyOption {
	return func(o *verifyOptions) {
		o.trustedRoots = pool
	}
}

// TrustSelfSigned allows verification to succeed for self-signed certificates
// or certificates signed by untrusted CAs embedded in the PDF.
// Deprecated: Use the fluent API doc.Verify().TrustSelfSigned(true) instead.
func TrustSelfSigned(trust bool) VerifyOption {
	return func(c *verifyOptions) {
		c.trustEmbedded = trust
	}
}

// CheckRevocation enables revocation checking.
func CheckRevocation(check bool) VerifyOption {
	return func(o *verifyOptions) {
		o.checkRevocation = check
	}
}

// AllowOCSP allows OCSP for revocation checking.
func AllowOCSP(allow bool) VerifyOption {
	return func(o *verifyOptions) {
		o.allowOCSP = allow
	}
}

// AllowCRL allows CRL for revocation checking.
func AllowCRL(allow bool) VerifyOption {
	return func(o *verifyOptions) {
		o.allowCRL = allow
	}
}

// ExternalChecks enables external network calls for revocation.
func ExternalChecks(enable bool) VerifyOption {
	return func(o *verifyOptions) {
		o.externalChecks = enable
	}
}

// AtTime sets the time at which to validate certificates.
func AtTime(t time.Time) VerifyOption {
	return func(o *verifyOptions) {
		o.validationTime = &t
	}
}

// ValidateFullChain sets whether to enforce cryptographic policy constraints (key size, algorithms) on the entire chain.
//
// By default (false), these constraints are only enforced on the leaf (signer) certificate.
// Revocation and standard trust verification are always performed on the full chain.
func ValidateFullChain(validate bool) VerifyOption {
	return func(o *verifyOptions) {
		o.validateFullChain = validate
	}
}

// TrustSignatureTime sets whether to trust the signature time.
func TrustSignatureTime(trust bool) VerifyOption {
	return func(o *verifyOptions) {
		o.trustSignatureTime = trust
	}
}

// RequireDigitalSignature requires the Digital Signature key usage bit.
func RequireDigitalSignature(require bool) VerifyOption {
	return func(o *verifyOptions) {
		o.requireDigSig = require
	}
}

// RequireNonRepudiation requires the Non-Repudiation key usage bit.
func RequireNonRepudiation(require bool) VerifyOption {
	return func(o *verifyOptions) {
		o.requireNonRepud = require
	}
}

// AllowedEKUs sets the allowed Extended Key Usages.
func AllowedEKUs(ekus ...x509.ExtKeyUsage) VerifyOption {
	return func(o *verifyOptions) {
		o.allowedEKUs = ekus
	}
}

// MinRSAKeySize constrains the minimum bit size for RSA keys.
func MinRSAKeySize(bits int) VerifyOption {
	return func(o *verifyOptions) {
		o.minRSAKeySize = bits
	}
}

// MinECDSAKeySize constrains the minimum curve size for ECDSA keys.
func MinECDSAKeySize(bits int) VerifyOption {
	return func(o *verifyOptions) {
		o.minECDSAKeySize = bits
	}
}

// AllowedAlgorithms restricts the permitted public key algorithms (e.g. x509.RSA, x509.ECDSA).
func AllowedAlgorithms(algos ...x509.PublicKeyAlgorithm) VerifyOption {
	return func(o *verifyOptions) {
		o.allowedAlgorithms = algos
	}
}

// VerifyResult contains the result of verification.
type VerifyResult struct {
	Valid      bool
	Signatures []SignatureVerifyResult
	Document   DocumentInfo
}

// SignatureVerifyResult contains verification result for a single signature.
type SignatureVerifyResult struct {
	SignatureInfo
	Valid          bool
	TrustedChain   bool
	Revoked        bool
	TimestampValid bool
	Errors         []error
	Warnings       []string
}

// DocumentInfo contains information about the PDF document.
type DocumentInfo struct {
	Author       string
	Creator      string
	Title        string
	Subject      string
	Producer     string
	Pages        int
	CreationDate time.Time
	ModDate      time.Time
}
