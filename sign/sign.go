package sign

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"

	"github.com/mattetti/filebuffer"
)

func SignFile(input string, output string, sign_data SignData) error {
	input_file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer func() {
		_ = input_file.Close()
	}()

	output_file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer func() {
		_ = output_file.Close()
	}()

	finfo, err := input_file.Stat()
	if err != nil {
		return err
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		return err
	}

	return Sign(input_file, output_file, rdr, size, sign_data)
}

func Sign(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 2

	context := SignContext{
		PDFReader:              rdr,
		InputFile:              input,
		OutputFile:             output,
		SignData:               sign_data,
		SignatureMaxLengthBase: uint32(hex.EncodedLen(512)),
	}

	// Fetch existing signatures
	existingSignatures, err := context.fetchExistingSignatures()
	if err != nil {
		return err
	}
	context.existingSignatures = existingSignatures

	err = context.SignPDF()
	if err != nil {
		return err
	}

	return nil
}

func (context *SignContext) SignPDF() error {
	// set defaults
	if context.SignData.Signature.CertType == 0 {
		context.SignData.Signature.CertType = 1
	}
	if context.SignData.Signature.DocMDPPerm == 0 {
		context.SignData.Signature.DocMDPPerm = 1
	}
	if !context.SignData.DigestAlgorithm.Available() {
		context.SignData.DigestAlgorithm = crypto.SHA256
	}
	if context.SignData.Appearance.Page == 0 {
		context.SignData.Appearance.Page = 1
	}

	context.OutputBuffer = filebuffer.New([]byte{})

	// Copy old file into new buffer.
	_, err := context.InputFile.Seek(0, 0)
	if err != nil {
		return err
	}
	if _, err := io.Copy(context.OutputBuffer, context.InputFile); err != nil {
		return err
	}

	// File always needs an empty line after %%EOF.
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return err
	}

	// Base size for signature.
	context.SignatureMaxLength = context.SignatureMaxLengthBase

	// If not a timestamp signature
	if context.SignData.Signature.CertType != TimeStampSignature {
		if context.SignData.Certificate == nil {
			return fmt.Errorf("certificate is required")
		}

		switch context.SignData.Certificate.SignatureAlgorithm.String() {
		case "SHA1-RSA":
		case "ECDSA-SHA1":
		case "DSA-SHA1":
			context.SignatureMaxLength += uint32(hex.EncodedLen(128))
		case "SHA256-RSA":
		case "ECDSA-SHA256":
		case "DSA-SHA256":
			context.SignatureMaxLength += uint32(hex.EncodedLen(256))
		case "SHA384-RSA":
		case "ECDSA-SHA384":
			context.SignatureMaxLength += uint32(hex.EncodedLen(384))
		case "SHA512-RSA":
		case "ECDSA-SHA512":
			context.SignatureMaxLength += uint32(hex.EncodedLen(512))
		}

		// Add size of digest algorithm twice (for file digist and signing certificate attribute)
		context.SignatureMaxLength += uint32(hex.EncodedLen(context.SignData.DigestAlgorithm.Size() * 2))

		// Add size for my certificate.
		degenerated, err := pkcs7.DegenerateCertificate(context.SignData.Certificate.Raw)
		if err != nil {
			return fmt.Errorf("failed to degenerate certificate: %w", err)
		}

		context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))

		// Add size of the raw issuer which is added by AddSignerChain
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(context.SignData.Certificate.RawIssuer)))

		// Add size for certificate chain.
		var certificate_chain []*x509.Certificate
		if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
			certificate_chain = context.SignData.CertificateChains[0][1:]
		}

		if len(certificate_chain) > 0 {
			for _, cert := range certificate_chain {
				degenerated, err := pkcs7.DegenerateCertificate(cert.Raw)
				if err != nil {
					return fmt.Errorf("failed to degenerate certificate in chain: %w", err)
				}

				context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))
			}
		}

		// Fetch revocation data before adding signature placeholder.
		// Revocation data can be quite large and we need to create enough space in the placeholder.
		if err := context.fetchRevocationData(); err != nil {
			return fmt.Errorf("failed to fetch revocation data: %w", err)
		}
	}

	// Add estimated size for TSA.
	// We can't kow actual size of TSA until after signing.
	//
	// Different TSA servers provide different response sizes, we
	// might need to make this configurable or detect and store.
	if context.SignData.TSA.URL != "" {
		context.SignatureMaxLength += uint32(hex.EncodedLen(9000))
	}

	// Create the signature object
	var signature_object []byte

	switch context.SignData.Signature.CertType {
	case TimeStampSignature:
		signature_object = context.createTimestampPlaceholder()
	default:
		signature_object = context.createSignaturePlaceholder()
	}

	// Write the new signature object
	context.SignData.objectId, err = context.addObject(signature_object)
	if err != nil {
		return fmt.Errorf("failed to add signature object: %w", err)
	}

	// Create visual signature (visible or invisible based on CertType)
	visible := false
	rectangle := [4]float64{0, 0, 0, 0}
	if context.SignData.Signature.CertType != ApprovalSignature && context.SignData.Appearance.Visible {
		return fmt.Errorf("visible signatures are only allowed for approval signatures")
	} else if context.SignData.Signature.CertType == ApprovalSignature && context.SignData.Appearance.Visible {
		visible = true
		rectangle = [4]float64{
			context.SignData.Appearance.LowerLeftX,
			context.SignData.Appearance.LowerLeftY,
			context.SignData.Appearance.UpperRightX,
			context.SignData.Appearance.UpperRightY,
		}
	}

	// Example usage: passing page number and default rect values
	visual_signature, err := context.createVisualSignature(visible, context.SignData.Appearance.Page, rectangle)
	if err != nil {
		return fmt.Errorf("failed to create visual signature: %w", err)
	}

	// Write the new visual signature object.
	context.VisualSignData.objectId, err = context.addObject(visual_signature)
	if err != nil {
		return fmt.Errorf("failed to add visual signature object: %w", err)
	}

	if context.SignData.Appearance.Visible {
		inc_page_update, err := context.createIncPageUpdate(context.SignData.Appearance.Page, context.VisualSignData.objectId)
		if err != nil {
			return fmt.Errorf("failed to create incremental page update: %w", err)
		}
		err = context.updateObject(context.VisualSignData.pageObjectId, inc_page_update)
		if err != nil {
			return fmt.Errorf("failed to add incremental page update object: %w", err)
		}
	}

	// Create a new catalog object
	catalog, err := context.createCatalog()
	if err != nil {
		return fmt.Errorf("failed to create catalog: %w", err)
	}

	// Write the new catalog object
	context.CatalogData.ObjectId, err = context.addObject(catalog)
	if err != nil {
		return fmt.Errorf("failed to add catalog object: %w", err)
	}

	// Write xref table
	if err := context.writeXref(); err != nil {
		return fmt.Errorf("failed to write xref: %w", err)
	}

	// Write trailer
	if err := context.writeTrailer(); err != nil {
		return fmt.Errorf("failed to write trailer: %w", err)
	}

	// Update byte range
	if err := context.updateByteRange(); err != nil {
		return fmt.Errorf("failed to update byte range: %w", err)
	}

	// Replace signature
	if err := context.replaceSignature(); err != nil {
		return fmt.Errorf("failed to replace signature: %w", err)
	}

	// Write final output
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	file_content := context.OutputBuffer.Buff.Bytes()

	if _, err := context.OutputFile.Write(file_content); err != nil {
		return err
	}

	return nil
}
