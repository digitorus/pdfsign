package verify

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/digitorus/pdf"
)

// DefaultVerifyOptions returns the default verification options following RFC 9336
//
// Deprecated: Use the fluent API instead:
//
//	doc, _ := pdfsign.OpenFile("document.pdf")
//	result := doc.Verify().TrustSelfSigned(false).MinRSAKeySize(2048)
//	if result.Valid() { ... }
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
		RequireDigitalSignatureKU:     true,             // Require Digital Signature key usage
		RequireNonRepudiation:         false,            // Don't require Non-Repudiation by default (optional)
		TrustSignatureTime:            false,            // Don't trust signatory-provided time by default
		ValidateTimestampCertificates: true,             // Always validate timestamp certificates
		AllowUntrustedRoots:           false,            // SECURE DEFAULT: Don't trust embedded certificates as roots
		EnableExternalRevocationCheck: false,            // SECURE DEFAULT: Don't make external network calls
		HTTPClient:                    nil,              // Use default HTTP client
		HTTPTimeout:                   10 * time.Second, // 10 second timeout for external checks
	}
}

// VerifyFile verifies a PDF file.
//
// Deprecated: Use the fluent API instead:
//
//	doc, _ := pdfsign.OpenFile("document.pdf")
//	if doc.Verify().Valid() { ... }
func VerifyFile(file *os.File) (apiResp *Response, err error) {
	return VerifyFileWithOptions(file, DefaultVerifyOptions())
}

// VerifyFileWithOptions verifies a PDF file with options.
//
// Deprecated: Use the fluent API instead:
//
//	doc, _ := pdfsign.OpenFile("document.pdf")
//	result := doc.Verify().MinRSAKeySize(2048).ExternalChecks(true)
//	if result.Valid() { ... }
func VerifyFileWithOptions(file *os.File, options *VerifyOptions) (apiResp *Response, err error) {
	finfo, _ := file.Stat()
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	return VerifyWithOptions(file, finfo.Size(), options)
}

// Verify verifies a PDF from a reader.
//
// Deprecated: Use the fluent API instead:
//
//	doc, _ := pdfsign.Open(reader, size)
//	if doc.Verify().Valid() { ... }
func Verify(file io.ReaderAt, size int64) (apiResp *Response, err error) {
	return VerifyWithOptions(file, size, DefaultVerifyOptions())
}

// VerifyWithOptions verifies a PDF from a reader with options.
//
// Deprecated: Use the fluent API instead:
//
//	doc, _ := pdfsign.Open(reader, size)
//	result := doc.Verify().TrustSelfSigned(false).Strict()
//	if result.Valid() { ... }
func VerifyWithOptions(file io.ReaderAt, size int64, options *VerifyOptions) (apiResp *Response, err error) {
	var documentInfo DocumentInfo

	defer func() {
		if r := recover(); r != nil {
			apiResp = nil
			err = fmt.Errorf("failed to verify file (%v)", r)
		}
	}()
	apiResp = &Response{}

	rdr, err := pdf.NewReaderEncrypted(file, size, passwordFunc(options.Password))
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
	root := rdr.Trailer().Key("Root")
	acroForm := root.Key("AcroForm")

	// Check SigFlags
	sigFlags := acroForm.Key("SigFlags")
	if sigFlags.IsNull() {
		return nil, fmt.Errorf("no digital signature in document (SigFlags missing)")
	}

	signers, found := VerifySignatures(rdr, file, size, options)
	if found == 0 {
		return nil, fmt.Errorf("inconsistent PDF: SigFlags implies signatures but none found in AcroForm Fields")
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("found signature fields but failed to process any signatures")
	}
	for _, signer := range signers {
		// Set any error message if present (Legacy API support)
		if len(signer.ValidationErrors) > 0 && apiResp.Error == "" {
			// For legacy single-string error, we use the first validation error
			apiResp.Error = signer.ValidationErrors[0].Error()
		}
		apiResp.Signers = append(apiResp.Signers, *signer)
	}

	if apiResp == nil {
		err = fmt.Errorf("document looks to have a signature but got no results")
	}

	apiResp.DocumentInfo = documentInfo

	return
}

// passwordFunc returns a password callback for pdf.NewReaderEncrypted that
// offers password once. An empty password means only the empty password is tried.
func passwordFunc(password string) func() string {
	return func() string {
		p := password
		password = ""
		return p
	}
}
