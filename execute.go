package pdfsign

import (
	"bytes"
	"fmt"
	"io"
	"time"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/render"
	"github.com/digitorus/pdfsign/sign"
)

// Write finalizes the document by executing all staged operations (signatures, form filling, initials).
// It performs incremental updates to the PDF and writes the resulting bytes to the provided writer.
//
// Calling Sign() more than once before Write() stages multiple signatures;
// each is applied in the order Sign() was called, as an incremental update
// chained on top of the previous signature's output (e.g. an approver
// countersigning a document someone else already signed). See
// ExampleDocument_Sign_multiple.
func (d *Document) Write(output io.Writer) (*Result, error) {
	result := &Result{
		Signatures: make([]SignatureInfo, 0, len(d.pendingSigns)),
		Document:   d,
	}

	// currentReader/currentSize/currentRdr track the input for the next
	// signing pass. When multiple signatures are staged, each pass must
	// build its incremental update on top of the PREVIOUS pass's signed
	// output, not the document's original unsigned bytes, or the writer
	// ends up with N unrelated single-signature copies concatenated
	// together instead of one document with N chained signatures.
	var currentReader io.ReaderAt = io.NewSectionReader(d.reader, 0, d.size)
	currentSize := d.size
	currentRdr := d.rdr

	for i, sb := range d.pendingSigns {
		// Validate Format
		switch sb.format {
		case PAdES_B_LTA, C2PA, JAdES_B_T:
			return nil, fmt.Errorf("signature format %v is not currently supported", sb.format)
		case PAdES_B_T:
			if sb.tsa == "" {
				return nil, fmt.Errorf("PAdES_B_T format requires a Timestamp Authority (TSA) URL")
			}
		}

		// Convert SignBuilder to sign.SignData
		signData := sign.SignData{
			Signer:             sb.signer,
			Certificate:        sb.cert,
			CertificateChains:  sb.chains,
			DigestAlgorithm:    sb.digest,
			Updates:            make(map[uint32][]byte),
			CompressLevel:      d.compressLevel,
			RevocationFunction: sb.revocationFunc,
		}

		// Use default revocation function if none provided
		if signData.RevocationFunction == nil {
			// configure defaults based on format
			embedRevocation := true
			if sb.format == PAdES_B {
				embedRevocation = false
			}

			// Create a default revocation function with options
			// By default we try both (EnableOCSP=true, EnableCRL=true) to maximize compatibility,
			// but we respect the PreferCRL setting.
			// We enable StopOnSuccess=true because usually one valid revocation proof is sufficient and optimal for size.
			signData.RevocationFunction = sign.NewRevocationFunction(sign.RevocationOptions{
				EmbedOCSP:     embedRevocation,
				EmbedCRL:      embedRevocation,
				PreferCRL:     sb.preferCRL, // Use builder preference
				StopOnSuccess: true,         // Stop after first success to save space
				Cache:         sb.revocationCache,
			})
		}

		// Apply pending form field updates
		fieldUpdates, err := d.applyPendingFields()
		if err != nil {
			return nil, fmt.Errorf("failed to apply pending fields: %w", err)
		}
		for id, content := range fieldUpdates {
			signData.Updates[id] = content
		}

		// For now simple assignment, assumes 1 signature usually.
		signData.PreSignCallback = d.applyInitials(sb)

		// Set signature info
		name := sb.signerName
		if name == "" && sb.cert != nil {
			name = sb.cert.Subject.CommonName
		}
		signData.Signature.Info.Name = name
		signData.Signature.Info.Reason = sb.reason
		signData.Signature.Info.Location = sb.location
		signData.Signature.Info.ContactInfo = sb.contact

		// Map signature type
		switch sb.sigType {
		case ApprovalSignature:
			signData.Signature.CertType = sign.ApprovalSignature
		case CertificationSignature:
			signData.Signature.CertType = sign.CertificationSignature
			signData.Signature.DocMDPPerm = sign.DocMDPPerm(sb.permission)
		case DocumentTimestamp:
			signData.Signature.CertType = sign.TimeStampSignature
		}

		// TSA configuration
		if sb.tsa != "" {
			signData.TSA.URL = sb.tsa
			signData.TSA.Username = sb.tsaUser
			signData.TSA.Password = sb.tsaPass
		}

		// Appearance configuration
		if sb.appearance != nil {
			signData.Appearance.Visible = true
			signData.Appearance.Page = uint32(sb.appPage)
			signData.Appearance.LowerLeftX = sb.appX * sb.unit
			signData.Appearance.LowerLeftY = sb.appY * sb.unit
			signData.Appearance.UpperRightX = (sb.appX * sb.unit) + sb.appearance.width
			signData.Appearance.UpperRightY = (sb.appY * sb.unit) + sb.appearance.height

			// Use the custom renderer from the internal render package
			signData.Appearance.Renderer = render.NewAppearanceRenderer(
				sb.appearance.RenderInfo(),
				sb.signerName,
				sb.reason,
				sb.location,
			)
		}

		// Execute signing using existing sign package.
		// Wrap the current reader as a ReadSeeker so signing always executes
		// for any io.ReaderAt implementation (not just *os.File).
		rs := io.NewSectionReader(currentReader, 0, currentSize)

		isLast := i == len(d.pendingSigns)-1
		var buf bytes.Buffer
		err = sign.SignWithData(rs, &buf, currentRdr, currentSize, signData)
		if err != nil {
			return nil, err
		}

		if isLast {
			if _, err := output.Write(buf.Bytes()); err != nil {
				return nil, fmt.Errorf("failed to write signed document: %w", err)
			}
		} else {
			signedBytes := buf.Bytes()
			newRdr, err := pdflib.NewReader(bytes.NewReader(signedBytes), int64(len(signedBytes)))
			if err != nil {
				return nil, fmt.Errorf("failed to re-open intermediate signed document: %w", err)
			}
			currentReader = bytes.NewReader(signedBytes)
			currentSize = int64(len(signedBytes))
			currentRdr = newRdr
		}

		// Build result info
		info := SignatureInfo{
			SignerName:  sb.signerName,
			Reason:      sb.reason,
			Location:    sb.location,
			Contact:     sb.contact,
			SigningTime: time.Now(),
			Format:      sb.format,
		}
		if sb.cert != nil {
			info.Certificate = sb.cert
			if sb.signerName == "" {
				info.SignerName = sb.cert.Subject.CommonName
			}
		}
		result.Signatures = append(result.Signatures, info)
	}

	return result, nil
}
