package verify

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"bitbucket.org/digitorus/pdf"
	"bitbucket.org/digitorus/pdfsign/revocation"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"strconv"
	"strings"

	"golang.org/x/crypto/ocsp"
)

type Response struct {
	Error string

	DocumentInfo DocumentInfo
	Signers      []Signer
}

type Signer struct {
	Name               string
	Reason             string
	Location           string
	ContactInfo        string
	ValidSignature     bool
	TrustedIssuer      bool
	RevokedCertificate bool
	Certificates       []Certificate
	TimeStamp          *timestamp.Timestamp
}

type Certificate struct {
	Certificate  *x509.Certificate
	VerifyError  string
	OCSPResponse *ocsp.Response
	OCSPEmbedded bool
	CRLRevoked   time.Time
	CRLEmbedded  bool
}

func File(file *os.File) (apiResp *Response, err error) {
	finfo, _ := file.Stat()
	file.Seek(0, 0)

	return Reader(file, finfo.Size())
}

func Reader(file io.ReaderAt, size int64) (apiResp *Response, err error) {
	var documentInfo DocumentInfo

	defer func() {
		if r := recover(); r != nil {
			apiResp = nil
			err = fmt.Errorf("Failed to verify file (%v)", r)
		}
	}()
	apiResp = &Response{}

	rdr, err := pdf.NewReader(file, size)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %v", err)
	}

	// AcroForm will contain a SigFlags value if the form contains a digital signature
	t := rdr.Trailer().Key("Root").Key("AcroForm").Key("SigFlags")
	if t.IsNull() {
		return nil, fmt.Errorf("No digital signature in document")
	}

	// Walk over the cross references in the document
	for _, x := range rdr.Xref() {
		// Get the xref object Value
		v := rdr.Resolve(x.Ptr(), x.Ptr())

		// get document info
		getDocumentInfo(v, &documentInfo)

		// We must have a Filter Adobe.PPKLite
		if v.Key("Filter").Name() != "Adobe.PPKLite" {
			continue
		}

		signer := Signer{
			Name:        v.Key("Name").Text(),
			Reason:      v.Key("Reason").Text(),
			Location:    v.Key("Location").Text(),
			ContactInfo: v.Key("ContactInfo").Text(),
		}

		// (Required) The signature value. When ByteRange is present, the
		// value shall be a hexadecimal string (see 7.3.4.3, â€œHexadecimal
		// Stringsâ€) representing the value of the byte range digest.
		// For public-key signatures, Contents should be either a DER-encoded
		// PKCS#1 binary data object or a DER-encoded PKCS#7 binary data object.
		// Space for the Contents value must be allocated before the message
		// digest is computed. (See 7.3.4, â€œString Objectsâ€œ)
		p7, err := pkcs7.Parse([]byte(v.Key("Contents").RawString()))
		if err != nil {
			//fmt.Println(err)
			continue
		}

		// An array of pairs of integers (starting byte offset, length in
		// bytes) that shall describe the exact byte range for the digest
		// calculation. Multiple discontiguous byte ranges shall be used to
		// describe a digest that does not include the signature value (the
		// Contents entry) itself.
		for i := 0; i < v.Key("ByteRange").Len(); i++ {
			// As the byte range comes in pairs, we increment one extra
			i++

			// Read the byte range from the raw file and add it to the contents.
			// This content will be hashed with the corresponding algorithm to
			// verify the signature.

			content, err := ioutil.ReadAll(io.NewSectionReader(file, v.Key("ByteRange").Index(i-1).Int64(), v.Key("ByteRange").Index(i).Int64()))
			if err != nil {
				apiResp.Error = fmt.Sprintln("Failed to get ByteRange:", i, err)
			}

			p7.Content = append(p7.Content, content...)
		}

		// Signer certificate
		// http://www.alvestrand.no/objectid/1.2.840.113549.1.9.html
		// http://www.alvestrand.no/objectid/1.2.840.113583.1.1.8.html
		var isn []byte
		for _, s := range p7.Signers {
			isn = s.IssuerAndSerialNumber.IssuerName.FullBytes
			//for _, a := range s.AuthenticatedAttributes {
			//fmt.Printf("A: %v, %#v\n", s.IssuerAndSerialNumber.SerialNumber, a.Type)
			//}

			// Timestamp
			// http://www.alvestrand.no/objectid/1.2.840.113549.1.9.16.2.14.html
			// Timestamp
			// 1.2.840.113549.1.9.16.2.14 - RFC 3161 id-aa-timeStampToken
			for _, attr := range s.UnauthenticatedAttributes {
				//fmt.Printf("U: %v, %#v\n", s.IssuerAndSerialNumber.SerialNumber, attr.Type)

				if attr.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}) {
					//fmt.Println("Found timestamp")

					signer.TimeStamp, err = timestamp.Parse(attr.Value.Bytes)
					if err != nil {
						apiResp.Error = fmt.Sprintln("Failed to parse timestamp", err)
					} else {
						r := bytes.NewReader(s.EncryptedDigest)
						h := crypto.SHA256.New()
						b := make([]byte, 32)
						for {
							n, err := r.Read(b)
							if err == io.EOF {
								break
							}

							h.Write(b[:n])
						}

						if !bytes.Equal(h.Sum(nil), signer.TimeStamp.HashedMessage) {
							apiResp.Error = fmt.Sprintln("Hash in timestamp is different from pkcs7")
						}

						break
					}
				}
			}
		}

		// Directory of certificates, including OCSP
		//var ica *x509.Certificate
		certPool := x509.NewCertPool()
		for _, cert := range p7.Certificates {
			certPool.AddCert(cert)
			if bytes.Equal(isn, cert.RawSubject) {
				//ica = cert
			}
		}

		// Verify the digital signature of the pdf file.
		err = p7.VerifyWithChain(certPool)
		if err != nil {
			err = p7.Verify()
			if err == nil {
				signer.ValidSignature = true
				signer.TrustedIssuer = false
			} else {
				apiResp.Error = fmt.Sprintln("Failed to verify signature:", err)
			}
		} else {
			signer.ValidSignature = true
			signer.TrustedIssuer = true
		}

		// PDF signature certificate revocation information attribute (1.2.840.113583.1.1.8)
		var revInfo revocation.InfoArchival
		p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, &revInfo)

		// Parse OCSP response
		var ocspStatus = make(map[string]*ocsp.Response)
		for _, o := range revInfo.OCSP {
			resp, err := ocsp.ParseResponse(o.FullBytes, nil)
			if err != nil {
				apiResp.Error = fmt.Sprintln("Failed to parse or verify OCSP response", err)
				ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = nil
			} else {
				ocspStatus[fmt.Sprintf("%x", resp.SerialNumber)] = resp
			}
		}

		// Build certificate chains and verify revocation status
		for _, cert := range p7.Certificates {
			var c Certificate
			c.Certificate = cert

			chain, err := cert.Verify(x509.VerifyOptions{
				Intermediates: certPool,
				CurrentTime:   cert.NotBefore,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})

			if err != nil {
				c.VerifyError = err.Error()
			}

			if resp, ok := ocspStatus[fmt.Sprintf("%x", cert.SerialNumber)]; ok {
				c.OCSPResponse = resp
				c.OCSPEmbedded = true

				if resp.Status != ocsp.Good {
					signer.RevokedCertificate = true
				}

				if len(chain) > 0 && len(chain[0]) > 1 {
					issuer := chain[0][1]
					if resp.Certificate != nil {
						err = resp.Certificate.CheckSignatureFrom(issuer)
						if err != nil {
							apiResp.Error = fmt.Sprintln("OCSP signing cerificate not from certificate issuer:", err)
						}
					} else {
						// CA Signed response
						err = resp.CheckSignatureFrom(issuer)
						if err != nil {
							apiResp.Error = fmt.Sprintln("Failed to verify OCSP response signature:", err)
						}
					}
				}
			} else {
				// Check OCSP status for certificate out of band
			}

			// Add certificate to result
			signer.Certificates = append(signer.Certificates, c)
		}

		// Certificate revocation lists when included in this document
		for _, crl := range p7.CRLs {
			//var crlissuer *pkix.Name
			//crlissuerdr.FillFromRDNSequence(&crl.TBSCertList.Issuer)
			if len(crl.TBSCertList.RevokedCertificates) > 0 {

			}
			//apiResp.Error = fmt.Sprintf("CRL %v , with %d entries\n", crl.TBSCertList.Issuer, len(crl.TBSCertList.RevokedCertificates))
			// TODO(vanbroup): Check revocation via CRL
			// signer.RevokedCertificate = true
		}

		// Parse CRL file
		for _, c := range revInfo.CRL {
			crl, err := x509.ParseCRL(c.FullBytes)
			if err != nil {
				apiResp.Error = fmt.Sprintln("Failed to parse or verify embedded CRL")
			}

			if len(crl.TBSCertList.RevokedCertificates) > 0 {

			}

			//var crlissuer *pkix.Name
			//crlissuerdr.FillFromRDNSequence(&crl.TBSCertList.Issuer)
			//apiResp.Error = fmt.Sprintf("CRL %v , with %d entries\n", crl.TBSCertList.Issuer, len(crl.TBSCertList.RevokedCertificates))
			// TODO(vanbroup): Check revocation via CRL
			// signer.RevokedCertificate = true
		}

		// If SubFilter is adbe.pkcs7.detached or adbe.pkcs7.sha1, this entry
		// shall not be used, and the certificate chain shall be put in the PKCS#7
		// envelope in Contents.
		//v.Key("Cert").Text()

		apiResp.Signers = append(apiResp.Signers, signer)
	}

	if apiResp == nil {
		err = fmt.Errorf("Document looks to have a signature but got no results")
	}

	apiResp.DocumentInfo = documentInfo

	return
}

// DocumentInfo contains document information
type DocumentInfo struct {
	Author,
	Creator,
	Hash,
	Name,
	Permission,
	Producer,
	Subject,
	Title string

	Pages    int
	Keywords []string
	ModDate,
	CreationDate time.Time
}

// getDocumentInfo parses document information
func getDocumentInfo(v pdf.Value, documentInfo *DocumentInfo) {
	keys := []string{"Author", "CreationDate", "Creator", "Hash", "Keywords", "ModDate",
		"Name", "Pages", "Permission", "Producer", "Subject", "Title"}

	for _, key := range keys {
		value := v.Key(key)
		if !value.IsNull() {
			// get string value
			valueStr := value.Text()

			// get struct field
			elem := reflect.ValueOf(documentInfo).Elem()
			field := elem.FieldByName(key)

			switch key {
			// parse dates
			case "CreationDate", "ModDate":
				t, _ := parseDate(valueStr)
				field.Set(reflect.ValueOf(t))
			// parse pages
			case "Pages":
				i, _ := strconv.Atoi(valueStr)
				documentInfo.Pages = i
			case "Keywords":
				documentInfo.Keywords = parseKeywords(valueStr)
			default:
				field.Set(reflect.ValueOf(valueStr))
			}
		}
	}
}

// parseDate parses pdf formatted dates
func parseDate(v string) (time.Time, error) {
	//PDF Date Format
	//(D:YYYYMMDDHHmmSSOHH'mm')
	//
	//where
	//
	//YYYY is the year
	//MM is the month
	//DD is the day (01-31)
	//HH is the hour (00-23)
	//mm is the minute (00-59)
	//SS is the second (00-59)
	//O is the relationship of local time to Universal Time (UT), denoted by one of the characters +, -, or Z (see below)
	//HH followed by ' is the absolute value of the offset from UT in hours (00-23)
	//mm followed by ' is the absolute value of the offset from UT in minutes (00-59)

	//2006-01-02T15:04:05Z07:00
	//(D:YYYYMMDDHHmmSSOHH'mm')
	return time.Parse("D:20060102150405Z07'00'", v)
}

// parseKeywords parses keywords pdf meta data
func parseKeywords(value string) []string {
	//keywords must be separated by commas or semicolons or could be just separated with spaces, after the semicolon could be a space
	//https://stackoverflow.com/questions/44608608/the-separator-between-keywords-in-pdf-meta-data
	separators := []string{", ", ": ", ",", ":", " "}
	for _, s := range separators {
		if strings.Contains(value, s) {
			return strings.Split(value, s)
		}
	}

	return []string{value}
}

func walk(t pdf.Value, pad int) {
	for _, k := range t.Keys() {
		v := t.Key(k)
		if v.Kind() == pdf.Array || v.Kind() == pdf.Dict {
			pad++
			walk(v, pad)
		}
	}
}
