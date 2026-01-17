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
	root := rdr.Trailer().Key("Root")
	acroForm := root.Key("AcroForm")

	// Check SigFlags
	sigFlags := acroForm.Key("SigFlags")
	if sigFlags.IsNull() {
		return nil, fmt.Errorf("no digital signature in document (SigFlags missing)")
	}

	// Iterate over the AcroForm Fields to find signature fields
	fields := acroForm.Key("Fields")
	foundSignature := false

	var traverse func(pdf.Value) bool
	traverse = func(arr pdf.Value) bool {
		if !arr.IsNull() && arr.Kind() == pdf.Array {
			for i := 0; i < arr.Len(); i++ {
				field := arr.Index(i)

				// Check if this field is a signature
				if field.Key("FT").Name() == "Sig" {
					// Get the signature dictionary (the value of the field)
					v := field.Key("V")

					// Verify if it is a signature dictionary and has the correct filter
					if !v.IsNull() && v.Key("Filter").Name() == "Adobe.PPKLite" {
						foundSignature = true

						// Use the new modular signature processing function
						signer, errorMsg, err := VerifySignature(v, file, size, options)
						if err != nil {
							// Skip this signature if there's a critical error
							return true // Continue to next
						}

						// Set any error message if present
						if errorMsg != "" && apiResp.Error == "" {
							apiResp.Error = errorMsg
						}

						apiResp.Signers = append(apiResp.Signers, *signer)
					}
				}

				// Recurse into Kids
				kids := field.Key("Kids")
				if !kids.IsNull() {
					if !traverse(kids) {
						return false
					}
				}
			}
		}
		return true
	}

	if !fields.IsNull() {
		traverse(fields)
	}

	if !foundSignature {
		// Fallback: This might occur if SigFlags is set but fields are empty or not found properly.
		// In strictly compliant PDFs, this shouldn't happen if SigFlags implies signatures.
		// However, adhering to the "Line of Sight" rule, we return what we found (or didn't).
		// If we want to be robust against malformed PDFs that have detached signature objects
		// floating around without being in Fields, we would keep the old scan.
		// Given the direction to optimize, we rely on standard structure.
	}

	if apiResp == nil {
		err = fmt.Errorf("document looks to have a signature but got no results")
	}

	apiResp.DocumentInfo = documentInfo

	return
}
