package sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const signatureByteRangePlaceholder = "/ByteRange[0 ********** ********** **********]"

func (context *SignContext) createSignaturePlaceholder() []byte {
	// Using a buffer because it's way faster than concatenating.
	var signature_buffer bytes.Buffer

	signature_buffer.WriteString("<<\n")
	signature_buffer.WriteString(" /Type /Sig\n")
	signature_buffer.WriteString(" /Filter /Adobe.PPKLite\n")
	signature_buffer.WriteString(" /SubFilter /adbe.pkcs7.detached\n")

	signature_buffer.WriteString(context.createPropBuild())

	// Create a placeholder for the byte range string, we will replace it later.
	signature_buffer.WriteString(" " + signatureByteRangePlaceholder)

	// Create a placeholder for the actual signature content, we will replace it later.
	signature_buffer.WriteString(" /Contents<")
	signature_buffer.Write(bytes.Repeat([]byte("0"), int(context.SignatureMaxLength)))
	signature_buffer.WriteString(">\n")

	switch context.SignData.Signature.CertType {
	case CertificationSignature, UsageRightsSignature:
		signature_buffer.WriteString(" /Reference [\n") // start array of signature reference dictionaries
		signature_buffer.WriteString(" << /Type /SigRef\n")
	}

	switch context.SignData.Signature.CertType {
	// Certification signature (also known as an author signature)
	case CertificationSignature:
		signature_buffer.WriteString(" /TransformMethod /DocMDP\n")

		// Entries in the DocMDP transform parameters dictionary (Table 257)
		signature_buffer.WriteString(" /TransformParams <<\n")

		// Type [name]: (Optional) The type of PDF object that this dictionary describes;
		//   if present, shall be TransformParams for a transform parameters dictionary.
		signature_buffer.WriteString("   /Type /TransformParams\n")

		// (Optional) The access permissions granted for this document. Changes to
		//   a PDF that are incremental updates which include only the data necessary
		//   to add DSS’s 12.8.4.3, "Document Security Store (DSS)" and/or document
		//   timestamps 12.8.5, "Document timestamp (DTS) dictionary" to the
		//   document shall not be considered as changes to the document as defined
		//   in the choices below.
		//
		//   Valid values shall be:
		//     1 No changes to the document shall be permitted; any change to the document
		//       shall invalidate the signature.
		//     2 Permitted changes shall be filling in forms, instantiating page templates,
		//       and signing; other changes shall invalidate the signature.
		//     3 Permitted changes shall be the same as for 2, as well as annotation creation,
		//       deletion, and modification; other changes shall invalidate the signature.
		//
		//   (Default value: 2.)
		signature_buffer.WriteString("   /P " + strconv.Itoa(int(context.SignData.Signature.DocMDPPerm)))

		// V [name]: (Optional) The DocMDP transform parameters dictionary version. The only valid value shall be 1.2.
		//   Default value: 1.2. (This value is a name object, not a number.)
		signature_buffer.WriteString("   /V /1.2\n")

	// Usage rights signature (deprecated in PDF 2.0)
	case UsageRightsSignature:
		signature_buffer.WriteString("   /TransformMethod /UR3\n")

		// Entries in the UR transform parameters dictionary (Table 258)
		signature_buffer.WriteString("   /TransformParams <<\n")
		signature_buffer.WriteString("     /Type /TransformParams\n")
		signature_buffer.WriteString("     /V /2.2\n")

	// Approval signatures (also known as recipient signatures)
	case ApprovalSignature:
		// Used to detect modifications to a list of form fields specified in TransformParams; see
		// 12.8.2.4, "FieldMDP"
		signature_buffer.WriteString("   /TransformMethod /FieldMDP\n")

		// Entries in the FieldMDP transform parameters dictionary (Table 259)
		signature_buffer.WriteString("   /TransformParams <<\n")

		// Type [name]: (Optional) The type of PDF object that this dictionary describes;
		//   if present, shall be TransformParams for a transform parameters dictionary.
		signature_buffer.WriteString("     /Type /TransformParams\n")

		// Action [name]: (Required) A name that, along with the Fields array, describes
		//   which form fields do not permit changes after the signature is applied.
		//   Valid values shall be:
		//     All - All form fields
		//     Include - Only those form fields specified in Fields.
		//     Exclude - Only those form fields not specified in Fields.
		signature_buffer.WriteString("     /Action /All\n")

		// V [name]: (Optional; required for PDF 1.5 and later) The transform parameters
		//   dictionary version. The value for PDF 1.5 and later shall be 1.2.
		//   Default value: 1.2. (This value is a name object, not a number.)
		signature_buffer.WriteString("     /V /1.2\n")
	}

	// (Required) A name identifying the algorithm that shall be used when computing the digest if not specified in the
	// certificate. Valid values are MD5, SHA1 SHA256, SHA384, SHA512 and RIPEMD160
	switch context.SignData.DigestAlgorithm {
	case crypto.MD5:
		signature_buffer.WriteString("   /DigestMethod /MD5\n")
	case crypto.SHA1:
		signature_buffer.WriteString("   /DigestMethod /SHA1\n")
	case crypto.SHA256:
		signature_buffer.WriteString("   /DigestMethod /SHA256\n")
	case crypto.SHA384:
		signature_buffer.WriteString("   /DigestMethod /SHA384\n")
	case crypto.SHA512:
		signature_buffer.WriteString("   /DigestMethod /SHA512\n")
	case crypto.RIPEMD160:
		signature_buffer.WriteString("   /DigestMethod /RIPEMD160\n")
	}

	switch context.SignData.Signature.CertType {
	case CertificationSignature, UsageRightsSignature:
		signature_buffer.WriteString("   >>\n") // close TransformParams
		signature_buffer.WriteString(" >>")     // close SigRef
		signature_buffer.WriteString(" ]")      // end of reference
	}

	switch context.SignData.Signature.CertType {
	case ApprovalSignature:
		signature_buffer.WriteString(" >>\n")
	}

	if context.SignData.Signature.Info.Name != "" {
		signature_buffer.WriteString(" /Name ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Name))
		signature_buffer.WriteString("\n")
	}
	if context.SignData.Signature.Info.Location != "" {
		signature_buffer.WriteString(" /Location ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Location))
		signature_buffer.WriteString("\n")
	}
	if context.SignData.Signature.Info.Reason != "" {
		signature_buffer.WriteString(" /Reason ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Reason))
		signature_buffer.WriteString("\n")
	}
	if context.SignData.Signature.Info.ContactInfo != "" {
		signature_buffer.WriteString(" /ContactInfo ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.ContactInfo))
		signature_buffer.WriteString("\n")
	}

	// (Optional) The time of signing. Depending on the signature handler, this may
	// be a normal unverified computer time or a time generated in a verifiable way
	// from a secure time server.
	//
	// This value should be used only when the time of signing is not available in the
	// signature. If SubFilter is ETSI.RFC3161, this entry should not be used and
	// should be ignored by a PDF processor.
	//
	// A timestamp can be embedded in a CMS binary data object (see 12.8.3.3, "CMS
	// (PKCS #7) signatures").
	if context.SignData.TSA.URL == "" && !context.SignData.Signature.Info.Date.IsZero() {
		signature_buffer.WriteString(" /M ")
		signature_buffer.WriteString(pdfDateTime(context.SignData.Signature.Info.Date))
		signature_buffer.WriteString("\n")
	}

	signature_buffer.WriteString(">>\n")

	return signature_buffer.Bytes()
}

func (context *SignContext) createTimestampPlaceholder() []byte {
	var timestamp_buffer bytes.Buffer

	timestamp_buffer.WriteString("<<\n")
	timestamp_buffer.WriteString(" /Type /DocTimeStamp\n")
	timestamp_buffer.WriteString(" /Filter /Adobe.PPKLite\n")
	timestamp_buffer.WriteString(" /SubFilter /ETSI.RFC3161\n")

	timestamp_buffer.WriteString(context.createPropBuild())

	// Create a placeholder for the byte range string, we will replace it later.
	timestamp_buffer.WriteString(" " + signatureByteRangePlaceholder)

	timestamp_buffer.WriteString(" /Contents<")
	timestamp_buffer.Write(bytes.Repeat([]byte("0"), int(context.SignatureMaxLength)))
	timestamp_buffer.WriteString(">\n")
	timestamp_buffer.WriteString(">>\n")

	return timestamp_buffer.Bytes()
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
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(crl.FullBytes)))
	}
	for _, ocsp := range context.SignData.RevocationData.OCSP {
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(ocsp.FullBytes)))
	}

	return nil
}

func (context *SignContext) createSigningCertificateAttribute() (*pkcs7.Attribute, error) {
	hash := context.SignData.DigestAlgorithm.New()
	hash.Write(context.SignData.Certificate.Raw)

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificate
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // []ESSCertID, []ESSCertIDv2
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertID, ESSCertIDv2
				if context.SignData.DigestAlgorithm.HashFunc() != crypto.SHA1 &&
					context.SignData.DigestAlgorithm.HashFunc() != crypto.SHA256 { // default SHA-256
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier
						b.AddASN1ObjectIdentifier(getOIDFromHashAlgorithm(context.SignData.DigestAlgorithm))
					})
				}
				b.AddASN1OctetString(hash.Sum(nil)) // certHash
			})
		})
	})

	sse, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	signingCertificate := pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}, // SigningCertificateV2
		Value: asn1.RawValue{FullBytes: sse},
	}
	if context.SignData.DigestAlgorithm.HashFunc() == crypto.SHA1 {
		signingCertificate.Type = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12} // SigningCertificate
	}
	return &signingCertificate, nil
}

func (context *SignContext) createSignature() ([]byte, error) {
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return nil, err
	}

	// Sadly we can't efficiently sign a file, we need to read all the bytes we want to sign.
	file_content := context.OutputBuffer.Buff.Bytes()

	// Collect the parts to sign.
	sign_content := make([]byte, 0)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[0]:(context.ByteRangeValues[0]+context.ByteRangeValues[1])]...)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[2]:(context.ByteRangeValues[2]+context.ByteRangeValues[3])]...)

	// Return the timestamp if we are signing a timestamp.
	if context.SignData.Signature.CertType == TimeStampSignature {
		// ETSI EN 319 142-1 V1.2.1
		//
		// Contents [Byte string ]: (Required) When the value of SubFilter is ETSI.RFC3161,
		// the value of Contents shall be the hexadecimal string (as defined in clause
		// 7.3.4.3 in ISO 32000-1 [1]) representing the value of TimeStampToken as
		// specified in IETF RFC 3161 [6] updated by IETF RFC 5816 [8]. The value of the
		// messageImprint field within the TimeStampToken shall be a hash of the bytes
		// of the document indicated by the ByteRange. The ByteRange shall cover the
		// entire document, including the Document Time-stamp dictionary but excluding
		// the TimeStampToken itself (the entry with key Contents).

		timestamp_response, err := context.GetTSA(sign_content)
		if err != nil {
			return nil, fmt.Errorf("get timestamp: %w", err)
		}

		ts, err := timestamp.ParseResponse(timestamp_response)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp: %w", err)
		}

		return ts.RawToken, nil
	}

	// Initialize pkcs7 signer.
	signed_data, err := pkcs7.NewSignedData(sign_content)
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}

	signed_data.SetDigestAlgorithm(getOIDFromHashAlgorithm(context.SignData.DigestAlgorithm))
	signingCertificate, err := context.createSigningCertificateAttribute()
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}

	signer_config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8},
				Value: context.SignData.RevocationData,
			},
			*signingCertificate,
		},
	}

	// Add the first certificate chain without our own certificate.
	var certificate_chain []*x509.Certificate
	if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
		certificate_chain = context.SignData.CertificateChains[0][1:]
	}

	// Add the signer and sign the data.
	if err := signed_data.AddSignerChain(context.SignData.Certificate, context.SignData.Signer, certificate_chain, signer_config); err != nil {
		return nil, fmt.Errorf("add signer chain: %w", err)
	}

	// PDF needs a detached signature, meaning the content isn't included.
	signed_data.Detach()

	if context.SignData.TSA.URL != "" {
		signature_data := signed_data.GetSignedData()

		timestamp_response, err := context.GetTSA(signature_data.SignerInfos[0].EncryptedDigest)
		if err != nil {
			return nil, fmt.Errorf("get timestamp: %w", err)
		}

		ts, err := timestamp.ParseResponse(timestamp_response)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp: %w", err)
		}

		_, err = pkcs7.Parse(ts.RawToken)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp token: %w", err)
		}

		timestamp_attribute := pkcs7.Attribute{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14},
			Value: asn1.RawValue{FullBytes: ts.RawToken},
		}
		if err := signature_data.SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{timestamp_attribute}); err != nil {
			return nil, err
		}
	}

	return signed_data.Finish()
}

func (context *SignContext) GetTSA(sign_content []byte) (timestamp_response []byte, err error) {
	sign_reader := bytes.NewReader(sign_content)
	ts_request, err := timestamp.CreateRequest(sign_reader, &timestamp.RequestOptions{
		Hash:         context.SignData.DigestAlgorithm,
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	ts_request_reader := bytes.NewReader(ts_request)
	req, err := http.NewRequest("POST", context.SignData.TSA.URL, ts_request_reader)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request (%s): %w", context.SignData.TSA.URL, err)
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
			defer func() {
				_ = resp.Body.Close()
			}()
			body, _ := io.ReadAll(resp.Body)
			return nil, errors.New("non success response (" + strconv.Itoa(code) + "): " + string(body))
		}

		return nil, errors.New("non success response (" + strconv.Itoa(code) + ")")
	}

	defer func() {
		_ = resp.Body.Close()
	}()
	timestamp_response_body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return timestamp_response_body, nil
}

func (context *SignContext) replaceSignature() error {
	signature, err := context.createSignature()
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	dst := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(dst, signature)

	if uint32(len(dst)) > context.SignatureMaxLength {
		log.Println("Signature too long, retrying with increased buffer size.")
		// set new base and try signing again
		context.SignatureMaxLengthBase += (uint32(len(dst)) - context.SignatureMaxLength) + 1
		return context.SignPDF()
	}

	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	file_content := context.OutputBuffer.Buff.Bytes()

	// Write the file content up to the signature
	if _, err := context.OutputBuffer.Write(file_content[context.ByteRangeValues[0]:context.ByteRangeValues[1]]); err != nil {
		return err
	}

	// Write new signature
	if _, err := context.OutputBuffer.Write([]byte("<")); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write([]byte(dst)); err != nil {
		return err
	}

	// Write 0s to ensure the signature remains the same size
	zeroPadding := bytes.Repeat([]byte("0"), int(context.SignatureMaxLength)-len(dst))
	if _, err := context.OutputBuffer.Write(zeroPadding); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write([]byte(">")); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write(file_content[context.ByteRangeValues[2] : context.ByteRangeValues[2]+context.ByteRangeValues[3]]); err != nil {
		return err
	}

	return nil
}

func (context *SignContext) fetchExistingSignatures() ([]SignData, error) {
	var signatures []SignData

	acroForm := context.PDFReader.Trailer().Key("Root").Key("AcroForm")
	if acroForm.IsNull() {
		return signatures, nil
	}

	fields := acroForm.Key("Fields")
	if fields.IsNull() {
		return signatures, nil
	}

	for i := 0; i < fields.Len(); i++ {
		field := fields.Index(i)
		if field.Key("FT").Name() == "Sig" {
			ptr := field.GetPtr()
			sig := SignData{
				objectId: uint32(ptr.GetID()),
			}
			signatures = append(signatures, sig)
		}
	}

	return signatures, nil
}

func (context *SignContext) createPropBuild() string {
	var buffer bytes.Buffer

	// Prop_Build [dictionary]: (Optional; PDF 1.5) A dictionary that may be used by a signature handler to
	// record information that captures the state of the computer environment used
	// for signing, such as the name of the handler used to create the signature,
	// software build date, version, and operating system.
	// The use of this dictionary is defined by Adobe PDF Signature Build Dictionary
	// Specification, which provides implementation guidelines.
	buffer.WriteString(" /Prop_Build <<\n")
	buffer.WriteString("   /App << /Name /Digitorus#20PDFSign >>\n")
	buffer.WriteString(" >>\n")

	return buffer.String()
}
