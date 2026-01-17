package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"

	"github.com/mattetti/filebuffer"
)

var errSignatureTooLong = fmt.Errorf("signature too long")

// SignFile signs a PDF file.
//
// Deprecated: Use pdf.OpenFile() and doc.Sign() instead.
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
		cerr := output_file.Close()
		if err == nil {
			err = cerr
		}
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

// SignWithData signs a PDF document using the provided signature data.
// It performs a single incremental update.
func SignWithData(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	if sign_data.Signature.Info.Date.IsZero() {
		sign_data.Signature.Info.Date = time.Now()
	}
	sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 2

	context := SignContext{
		PDFReader:              rdr,
		InputFile:              input,
		OutputFile:             output,
		SignData:               sign_data,
		SignatureMaxLengthBase: uint32(hex.EncodedLen(2048)),
		CompressLevel:          sign_data.CompressLevel,
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

// Deprecated: Use pdf.OpenFile() and doc.Sign() instead.
func Sign(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	return SignWithData(input, output, rdr, size, sign_data)
}

// SignPDF performs the signature operation.
func (context *SignContext) SignPDF() error {
	// set defaults
	context.applyDefaults()

	for retry := 0; retry < 5; retry++ {
		context.resetContext()

		// Copy old file into new buffer.
		if err := context.copyInputToOutput(); err != nil {
			return err
		}

		// Calculate signature size
		if err := context.calculateSignatureSize(); err != nil {
			return err
		}

		// Execute PreSignCallback if provided.
		if context.SignData.PreSignCallback != nil {
			if err := context.SignData.PreSignCallback(context); err != nil {
				return fmt.Errorf("pre-sign callback failed: %w", err)
			}
		}

		// Add signature object
		if err := context.addSignatureObject(); err != nil {
			return err
		}

		// Handle visual signature
		if err := context.handleVisualSignature(); err != nil {
			return err
		}

		// Create and add catalog
		if err := context.addCatalog(); err != nil {
			return err
		}

		// Finalize PDF structure (xref, trailer, byte range)
		if err := context.finalizePDFStructure(); err != nil {
			return err
		}

		// Replace signature placeholder with actual signature
		if err := context.replaceSignature(); err != nil {
			if err == errSignatureTooLong {
				continue
			}
			return fmt.Errorf("failed to replace signature: %w", err)
		}

		// Success!
		break
	}

	// Write final output
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	// We are still using the buffer here as refactoring that away is a larger task
	// involving the SignContext struct itself.
	file_content := context.OutputBuffer.Buff.Bytes()

	if _, err := context.OutputFile.Write(file_content); err != nil {
		return err
	}

	return nil
}

func (context *SignContext) applyDefaults() {
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
}

func (context *SignContext) resetContext() {
	context.OutputBuffer = filebuffer.New([]byte{})
	context.lastXrefID = 0
	context.newXrefEntries = nil
	context.updatedXrefEntries = nil
	context.ExtraAnnots = nil
	context.CatalogData = CatalogData{}
	context.VisualSignData = VisualSignData{}
}

func (context *SignContext) copyInputToOutput() error {
	if _, err := context.InputFile.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(context.OutputBuffer, context.InputFile); err != nil {
		return err
	}
	// File always needs an empty line after %%EOF.
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (context *SignContext) calculateSignatureSize() error {
	// Base size for signature.
	context.SignatureMaxLength = context.SignatureMaxLengthBase

	// If not a timestamp signature
	if context.SignData.Signature.CertType != TimeStampSignature {
		if context.SignData.Certificate == nil {
			return fmt.Errorf("certificate is required")
		}

		// Calculate signature size based on public key size
		var keySize int
		switch pub := context.SignData.Certificate.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = (pub.N.BitLen() + 7) / 8
		case *ecdsa.PublicKey:
			// ECDSA signature is (r, s) in ASN.1, roughly 2 * curve size + overhead
			curveBytes := (pub.Params().BitSize + 7) / 8
			keySize = 2*curveBytes + 32 // +32 for generous ASN.1 overhead
		default:
			keySize = 512 // Fallback default
		}
		context.SignatureMaxLength += uint32(hex.EncodedLen(keySize))

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
		if err := context.fetchRevocationData(); err != nil {
			return fmt.Errorf("failed to fetch revocation data: %w", err)
		}
	}

	// Add estimated size for TSA.
	if context.SignData.TSA.URL != "" {
		context.SignatureMaxLength += uint32(hex.EncodedLen(9000))
	}

	return nil
}

func (context *SignContext) addSignatureObject() error {
	var signature_object []byte
	switch context.SignData.Signature.CertType {
	case TimeStampSignature:
		signature_object = context.createTimestampPlaceholder()
	default:
		signature_object = context.createSignaturePlaceholder()
	}

	// Apply generic object updates if provided
	for id, content := range context.SignData.Updates {
		if err := context.UpdateObject(id, content); err != nil {
			return fmt.Errorf("failed to apply generic update for object %d: %w", id, err)
		}
	}

	// Write the new signature object
	var err error
	context.SignData.objectId, err = context.AddObject(signature_object)
	if err != nil {
		return fmt.Errorf("failed to add signature object: %w", err)
	}
	return nil
}

func (context *SignContext) handleVisualSignature() error {
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
	context.VisualSignData.objectId, err = context.AddObject(visual_signature)
	if err != nil {
		return fmt.Errorf("failed to add visual signature object: %w", err)
	}

	if context.SignData.Appearance.Visible {
		inc_page_update, err := context.createIncPageUpdate(context.SignData.Appearance.Page, context.VisualSignData.objectId)
		if err != nil {
			return fmt.Errorf("failed to create incremental page update: %w", err)
		}
		if err := context.UpdateObject(context.VisualSignData.pageObjectId, inc_page_update); err != nil {
			return fmt.Errorf("failed to add incremental page update object: %w", err)
		}
	}
	return nil
}

func (context *SignContext) addCatalog() error {
	// Create a new catalog object
	catalog, err := context.createCatalog()
	if err != nil {
		return fmt.Errorf("failed to create catalog: %w", err)
	}

	// Write the new catalog object
	context.CatalogData.ObjectId, err = context.AddObject(catalog)
	if err != nil {
		return fmt.Errorf("failed to add catalog object: %w", err)
	}
	return nil
}

func (context *SignContext) finalizePDFStructure() error {
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
	return nil
}
