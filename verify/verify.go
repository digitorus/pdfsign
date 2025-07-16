package verify

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

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
	Certificate  *x509.Certificate `json:"certificate"`
	VerifyError  string            `json:"verify_error"`
	OCSPResponse *ocsp.Response    `json:"ocsp_response"`
	OCSPEmbedded bool              `json:"ocsp_embedded"`
	CRLRevoked   time.Time         `json:"crl_revoked"`
	CRLEmbedded  bool              `json:"crl_embedded"`
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
	finfo, _ := file.Stat()
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	return Reader(file, finfo.Size())
}

func Reader(file io.ReaderAt, size int64) (apiResp *Response, err error) {
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
		signer, errorMsg, err := processSignature(v, file)
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
