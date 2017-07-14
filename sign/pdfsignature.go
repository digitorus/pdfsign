package sign

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"crypto/x509"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type pkiStatusInfo struct {
	Status       int
	StatusString string `asn1:"optional"`
	FailInfo     int    `asn1:"optional"`
}

// 2.4.2. Response Format
type TSAResponse struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue
}

var signatureMaxLength = uint32(1000000)
var signatureByteRangePlaceholder = "/ByteRange[0 ********** ********** **********]"

func (context *SignContext) createSignaturePlaceholder() (signature string, byte_range_start_byte int64, signature_contents_start_byte int64) {
	signature = strconv.Itoa(int(context.SignData.ObjectId)) + " 0 obj\n"
	signature += "<< /Type /Sig"
	signature += " /Filter /Adobe.PPKLite"
	signature += " /SubFilter /adbe.pkcs7.detached"

	byte_range_start_byte = int64(len(signature)) + 1

	// Create a placeholder for the byte range string, we will replace it later.
	signature += " " + signatureByteRangePlaceholder

	signature_contents_start_byte = int64(len(signature)) + 11

	// Create a placeholder for the actual signature content, we wil replace it later.
	signature += " /Contents<" + strings.Repeat("0", int(signatureMaxLength)) + ">"

	if !context.SignData.Signature.Approval {
		signature += " /Reference [" // array of signature reference dictionaries
		signature += " << /Type /SigRef"
		if context.SignData.Signature.CertType > 0 {
			signature += " /TransformMethod /DocMDP"
			signature += " /TransformParams <<"
			signature += " /Type /TransformParams"
			signature += " /P " + strconv.Itoa(int(context.SignData.Signature.CertType))
			signature += " /V /1.2"
		} else {
			signature += " /TransformMethod /UR3"
			signature += " /TransformParams <<"
			signature += " /Type /TransformParams"
			signature += " /V /2.2"
		}

		signature += " >>" // close TransformParams
		signature += " >>"
		signature += " ]" // end of reference
	}

	if context.SignData.Signature.Info.Name != "" {
		signature += " /Name " + pdfString(context.SignData.Signature.Info.Name)
	}
	if context.SignData.Signature.Info.Location != "" {
		signature += " /Location " + pdfString(context.SignData.Signature.Info.Location)
	}
	if context.SignData.Signature.Info.Reason != "" {
		signature += " /Reason " + pdfString(context.SignData.Signature.Info.Reason)
	}
	if context.SignData.Signature.Info.ContactInfo != "" {
		signature += " /ContactInfo " + pdfString(context.SignData.Signature.Info.ContactInfo)
	}
	signature += " /M " + pdfDateTime(context.SignData.Signature.Info.Date)
	signature += " >>"
	signature += "\nendobj\n"

	return signature, byte_range_start_byte, signature_contents_start_byte
}

func (context *SignContext) createSignature() ([]byte, error) {

	// Sadly we can't efficiently sign a file, we need to read all the bytes we want to sign.
	context.OutputFile.Seek(0, 0)
	sign_buf := bytes.NewBuffer(nil)
	io.Copy(sign_buf, context.OutputFile)
	file_content := sign_buf.Bytes()

	// Collect the parts to sign.
	sign_content := make([]byte, 0)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[0]:(context.ByteRangeValues[0]+context.ByteRangeValues[1])]...)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[2]:(context.ByteRangeValues[2]+context.ByteRangeValues[3])]...)

	// Initialize pkcs7 signer.
	signed_data, err := pkcs7.NewSignedData(sign_content)
	if err != nil {
		return nil, err
	}

	signer_config := pkcs7.SignerInfoConfig{}

	TSATokenChain := make([][]*x509.Certificate, 0)

	if context.SignData.TSA.URL != "" {
		timestamp_response, err := context.GetTSA(sign_content)
		if err != nil {
			return nil, err
		}

		var rest []byte
		var resp TSAResponse
		if rest, err = asn1.Unmarshal(timestamp_response, &resp); err != nil {
			return nil, err
		}
		if len(rest) > 0 {
			return nil, errors.New("trailing data in Time-Stamp response")
		}

		if resp.Status.Status > 0 {
			return nil, errors.New(fmt.Sprintf("%s: %s", timestamp.FailureInfo(resp.Status.FailInfo).String(), resp.Status.StatusString))
		}

		timestamp_p7, err := pkcs7.Parse(resp.TimeStampToken.FullBytes)
		if err != nil {
			return nil, err
		}

		if len(resp.TimeStampToken.Bytes) == 0 {
			return nil, errors.New("no pkcs7 data in Time-Stamp response")
		}

		timestamp_attribute := pkcs7.Attribute{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14},
			Value: resp.TimeStampToken,
		}
		signer_config.ExtraUnsignedAttributes = append(signer_config.ExtraUnsignedAttributes, timestamp_attribute)

		tsa_certificate_pool := x509.NewCertPool()
		for _, certificate := range timestamp_p7.Certificates {
			tsa_certificate_pool.AddCert(certificate)
		}

		if len(timestamp_p7.Certificates) > 0 {
			TSATokenChain, err = timestamp_p7.Certificates[len(timestamp_p7.Certificates)-1].Verify(x509.VerifyOptions{
				Intermediates: tsa_certificate_pool,
			})
		}
	}

	if context.SignData.RevocationFunction != nil {
		if context.SignData.CertificateChains != nil && (len(context.SignData.CertificateChains) > 0) {
			certificate_chain := context.SignData.CertificateChains[0]
			if certificate_chain != nil && (len(certificate_chain) > 0) {
				for i, certificate := range certificate_chain {
					if i < len(certificate_chain)-1 {
						err = context.SignData.RevocationFunction(certificate, certificate_chain[i+1], &context.SignData.RevocationData)
						if err != nil {
							return nil, err
						}
					} else {
						err = context.SignData.RevocationFunction(certificate, nil, &context.SignData.RevocationData)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}

		if TSATokenChain != nil && (len(TSATokenChain) > 0) {
			certificate_chain := TSATokenChain[0]
			if certificate_chain != nil && (len(certificate_chain) > 0) {
				for i, certificate := range certificate_chain {
					if i < len(certificate_chain)-1 {
						err = context.SignData.RevocationFunction(certificate, certificate_chain[i+1], &context.SignData.RevocationData)
						if err != nil {
							return nil, err
						}
					} else {
						err = context.SignData.RevocationFunction(certificate, nil, &context.SignData.RevocationData)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}

		revocation_attribute := pkcs7.Attribute{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8},
			Value: context.SignData.RevocationData,
		}
		signer_config.ExtraSignedAttributes = append(signer_config.ExtraSignedAttributes, revocation_attribute)
	}

	// Add the first certificate chain without our own certificate.
	var certificate_chain []*x509.Certificate
	if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
		certificate_chain = context.SignData.CertificateChains[0][1:]
	}

	// Add the signer and sign the data.
	if err := signed_data.AddSignerChain(context.SignData.Certificate, context.SignData.Signer, certificate_chain, signer_config); err != nil {
		return nil, err
	}

	// PDF needs a detached signature, meaning the content isn't included.
	signed_data.Detach()

	return signed_data.Finish()
}

func (context *SignContext) GetTSA(sign_content []byte) (timestamp_response []byte, err error) {
	sign_reader := bytes.NewReader(sign_content)
	ts_request, err := timestamp.CreateRequest(sign_reader, &timestamp.RequestOptions{
		Certificates: true,
	})
	if err != nil {
		return nil, err
	}

	ts_request_reader := bytes.NewReader(ts_request)
	req, err := http.NewRequest("POST", context.SignData.TSA.URL, ts_request_reader)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/timestamp-query")
	req.Header.Add("Content-Transfer-Encoding", "binary")

	if context.SignData.TSA.Username != "" && context.SignData.TSA.Password != "" {
		req.SetBasicAuth(context.SignData.TSA.Username, context.SignData.TSA.Password)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	code := 0

	if resp != nil {
		code = resp.StatusCode
	}

	if err != nil || (code < 200 || code > 299) {
		if err == nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			err = errors.New("Non success response (" + strconv.Itoa(code) + "): " + string(body))
		} else {
			err = errors.New("Non success response (" + strconv.Itoa(code) + ")")
		}

		return nil, err
	}

	defer resp.Body.Close()
	timestamp_response_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return timestamp_response_body, nil
}

func (context *SignContext) replaceSignature() error {
	signature, err := context.createSignature()
	if err != nil {
		return err
	}

	dst := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(dst, signature)

	if uint32(len(dst)) > signatureMaxLength {
		return errors.New("Signature is too big to fit in reserved space.")
	}

	context.OutputFile.WriteAt(dst, context.ByteRangeValues[0]+context.ByteRangeValues[1]+1)

	return nil
}
