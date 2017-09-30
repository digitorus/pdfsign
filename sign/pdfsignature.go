package sign

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

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

var signatureByteRangePlaceholder = "/ByteRange[0 ********** ********** **********]"

func (context *SignContext) createSignaturePlaceholder() (dssd string, byte_range_start_byte int64, signature_contents_start_byte int64) {
	// Using a buffer because it's way faster than concatenating.
	var signature_buffer bytes.Buffer
	signature_buffer.WriteString(strconv.Itoa(int(context.SignData.ObjectId)) + " 0 obj\n")
	signature_buffer.WriteString("<< /Type /Sig")
	signature_buffer.WriteString(" /Filter /Adobe.PPKLite")
	signature_buffer.WriteString(" /SubFilter /adbe.pkcs7.detached")

	byte_range_start_byte = int64(signature_buffer.Len()) + 1

	// Create a placeholder for the byte range string, we will replace it later.
	signature_buffer.WriteString(" " + signatureByteRangePlaceholder)

	signature_contents_start_byte = int64(signature_buffer.Len()) + 11

	// Create a placeholder for the actual signature content, we wil replace it later.
	signature_buffer.WriteString(" /Contents<")
	signature_buffer.Write(bytes.Repeat([]byte("0"), int(context.SignatureMaxLength)))
	signature_buffer.WriteString(">")

	if !context.SignData.Signature.Approval {
		signature_buffer.WriteString(" /Reference [") // array of signature reference dictionaries
		signature_buffer.WriteString(" << /Type /SigRef")
		if context.SignData.Signature.CertType > 0 {
			signature_buffer.WriteString(" /TransformMethod /DocMDP")
			signature_buffer.WriteString(" /TransformParams <<")
			signature_buffer.WriteString(" /Type /TransformParams")
			signature_buffer.WriteString(" /P " + strconv.Itoa(int(context.SignData.Signature.CertType)))
			signature_buffer.WriteString(" /V /1.2")
		} else {
			signature_buffer.WriteString(" /TransformMethod /UR3")
			signature_buffer.WriteString(" /TransformParams <<")
			signature_buffer.WriteString(" /Type /TransformParams")
			signature_buffer.WriteString(" /V /2.2")
		}

		signature_buffer.WriteString(" >>") // close TransformParams
		signature_buffer.WriteString(" >>")
		signature_buffer.WriteString(" ]") // end of reference
	}

	if context.SignData.Signature.Info.Name != "" {
		signature_buffer.WriteString(" /Name ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Name))
	}
	if context.SignData.Signature.Info.Location != "" {
		signature_buffer.WriteString(" /Location ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Location))
	}
	if context.SignData.Signature.Info.Reason != "" {
		signature_buffer.WriteString(" /Reason ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Reason))
	}
	if context.SignData.Signature.Info.ContactInfo != "" {
		signature_buffer.WriteString(" /ContactInfo ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.ContactInfo))
	}
	signature_buffer.WriteString(" /M ")
	signature_buffer.WriteString(pdfDateTime(context.SignData.Signature.Info.Date))
	signature_buffer.WriteString(" >>")
	signature_buffer.WriteString("\nendobj\n")

	return signature_buffer.String(), byte_range_start_byte, signature_contents_start_byte
}

func (context *SignContext) fetchRevocationData() error {
	if context.SignData.RevocationFunction != nil {
		if context.SignData.CertificateChains != nil && (len(context.SignData.CertificateChains) > 0) {
			certificate_chain := context.SignData.CertificateChains[0]
			if certificate_chain != nil && (len(certificate_chain) > 0) {
				for i, certificate := range certificate_chain {
					if i < len(certificate_chain)-1 {
						err := context.SignData.RevocationFunction(certificate, certificate_chain[i+1], &context.SignData.RevocationData)
						if err != nil {
							return err
						}
					} else {
						err := context.SignData.RevocationFunction(certificate, nil, &context.SignData.RevocationData)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	// Calculate space needed for signature.
	for _, crl := range context.SignData.RevocationData.CRL {
		context.SignatureMaxLength += uint32(len(crl.FullBytes) * 2)
	}
	for _, ocsp := range context.SignData.RevocationData.OCSP {
		context.SignatureMaxLength += uint32(len(ocsp.FullBytes) * 2)
	}

	return nil
}

func (context *SignContext) createSignature() ([]byte, error) {
	context.OutputBuffer.Seek(0, 0)

	// Sadly we can't efficiently sign a file, we need to read all the bytes we want to sign.
	file_content := context.OutputBuffer.Buff.Bytes()

	// Collect the parts to sign.
	sign_content := make([]byte, 0)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[0]:(context.ByteRangeValues[0]+context.ByteRangeValues[1])]...)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[2]:(context.ByteRangeValues[2]+context.ByteRangeValues[3])]...)

	// Initialize pkcs7 signer.
	signed_data, err := pkcs7.NewSignedData(sign_content)
	if err != nil {
		return nil, err
	}

	signer_config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8},
				Value: context.SignData.RevocationData,
			},
		},
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

	if context.SignData.TSA.URL != "" {
		signature_data := signed_data.GetSignedData()

		timestamp_response, err := context.GetTSA(signature_data.SignerInfos[0].EncryptedDigest)
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

		_, err = pkcs7.Parse(resp.TimeStampToken.FullBytes)
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
		signature_data.SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{timestamp_attribute})
	}

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

	if uint32(len(dst)) > context.SignatureMaxLength {
		return errors.New("Signature is too big to fit in reserved space.")
	}

	context.OutputBuffer.Seek(0, 0)
	file_content := context.OutputBuffer.Buff.Bytes()

	context.OutputBuffer.Write(file_content[:(context.ByteRangeValues[0] + context.ByteRangeValues[1] + 1)])

	// Write new ByteRange.
	if _, err := context.OutputBuffer.Write([]byte(dst)); err != nil {
		return err
	}

	context.OutputBuffer.Write(file_content[(context.ByteRangeValues[0]+context.ByteRangeValues[1]+1)+int64(len(dst)):])

	return nil
}
