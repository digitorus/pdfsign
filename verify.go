package pdfsign

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/verify"
)

// Verify initializes a VerifyBuilder to configure and execute signature verification.
// The verification process is lazy and only executes when you access the results (e.g., via Valid() or Signatures()).
func (d *Document) Verify() *VerifyBuilder {
	return &VerifyBuilder{doc: d}
}

// execute performs the actual verification if not already done (lazy execution).
// Results are stored in the builder's internal fields. Safe to call
// concurrently from multiple goroutines on the same *VerifyBuilder: the
// underlying work runs exactly once (guarded by b.once), and every caller
// waiting on that call sees its results once it returns.
func (b *VerifyBuilder) execute() {
	b.once.Do(b.doExecute)
}

func (b *VerifyBuilder) doExecute() {
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
	vOpts.TrustedRoots = b.trustedRoots
	vOpts.SkipRevocationCheck = b.skipRevocationCheck
	vOpts.SkipOCSP = b.skipOCSP
	vOpts.SkipCRL = b.skipCRL
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
	if b.atTime != nil {
		vOpts.AtTime = *b.atTime
	}
	if b.httpTimeout > 0 {
		vOpts.HTTPTimeout = b.httpTimeout
	}
	if b.ctx != nil {
		vOpts.Context = b.ctx
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
		signer, err := verify.VerifySignature(sig.Object(), b.doc.reader, b.doc.size, vOpts)
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
			Warnings:       signer.Warnings,
		}

		// Add errors if any
		if len(signer.ValidationErrors) > 0 {
			sigResult.Errors = append(sigResult.Errors, signer.ValidationErrors...)
			sigResult.Valid = false
		}

		if signer.SignatureTime != nil {
			sigResult.SigningTime = *signer.SignatureTime
		}
		if len(signer.Certificates) > 0 {
			sigResult.Certificate = signer.Certificates[0].Certificate
		}
		if signer.TimeStamp != nil {
			ts := &TimestampInfo{Time: signer.TimeStamp.Time}
			if len(signer.TimeStamp.Certificates) > 0 {
				ts.Certificate = signer.TimeStamp.Certificates[0]
				ts.Authority = ts.Certificate.Subject.CommonName
			}
			sigResult.Timestamp = ts
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

// SignatureVerifyResult contains verification result for a single signature.
type SignatureVerifyResult struct {
	SignatureInfo
	Valid          bool
	TrustedChain   bool
	Revoked        bool
	TimestampValid bool
	Errors         []error
	Warnings       []error
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
