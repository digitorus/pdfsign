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

func VerifyFile(file *os.File) (apiResp *Response, err error) {
	return VerifyFileWithOptions(file, DefaultVerifyOptions())
}

func VerifyFileWithOptions(file *os.File, options *VerifyOptions) (apiResp *Response, err error) {
	finfo, _ := file.Stat()
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	return VerifyWithOptions(file, finfo.Size(), options)
}

func Verify(file io.ReaderAt, size int64) (apiResp *Response, err error) {
	return VerifyWithOptions(file, size, DefaultVerifyOptions())
}

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
