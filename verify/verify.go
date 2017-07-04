package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"bitbucket.org/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

type RevocationInfoArchival struct {
	CRL          RevCRL       `asn1:"tag:0,optional,explicit"`
	OCSP         RevOCSP      `asn1:"tag:1,optional,explicit"`
	OtherRevInfo OtherRevInfo `asn1:"tag:2,optional,explicit"`
}

type RevCRL []asn1.RawValue
type RevOCSP []asn1.RawValue

type OtherRevInfo struct {
	Type  asn1.ObjectIdentifier
	Value []byte
}

type Response struct {
	Error string

	DocumentInfo string
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

func Verify(file *os.File) (apiResp *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			apiResp = nil
			err = fmt.Errorf("Failed to verify file (%v)", r)
		}
	}()
	apiResp = &Response{}

	finfo, _ := file.Stat()
	size := finfo.Size()

	rdr, err := pdf.NewReader(file, size)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file")
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
					}

					break
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
			}
			//apiResp.Error = fmt.Sprintln("Failed to verify signature:", err)
		} else {
			signer.ValidSignature = true
			signer.TrustedIssuer = true
		}

		// PDF signature certificate revocation information attribute (1.2.840.113583.1.1.8)
		var revInfo RevocationInfoArchival
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

				if len(chain) > 1 && len(chain[0]) > 1 {
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

	return
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
