package sign

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"
	"strings"

	"github.com/digitorus/pkcs7"
)

var signatureMaxLength = uint32(11742)
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

	if context.SignData.Signature.Approval {
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

	// Remove trailing newline.
	file_content = file_content[:len(file_content)-1]

	// Collect the parts to sign.
	sign_content := make([]byte, context.ByteRangeValues[1]+context.ByteRangeValues[3])
	sign_content = append(sign_content, file_content[context.ByteRangeValues[0]:(context.ByteRangeValues[0]+context.ByteRangeValues[1])]...)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[2]:(context.ByteRangeValues[2]+context.ByteRangeValues[3])]...)

	// Initialize pkcs7 signer.
	signed_data, err := pkcs7.NewSignedData(sign_content)
	if err != nil {
		return nil, err
	}

	// Add the signer and sign the data.
	if err := signed_data.AddSignerChain(context.SignData.Certificate, context.SignData.Signer, context.SignData.CertificateChain, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	// PDF needs a detached signature, meaning the content isn't included.
	signed_data.Detach()

	return signed_data.Finish()
}

func (context *SignContext) replaceSignature() error {
	signature, err := context.createSignature()
	if err != nil {
		return err
	}

	dst := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(dst, signature)

	context.OutputFile.WriteAt(dst, context.ByteRangeValues[0]+context.ByteRangeValues[1])

	return nil
}
