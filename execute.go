package pdfsign

import (
	"fmt"
	"io"
	"time"

	"github.com/digitorus/pdfsign/internal/render"
	"github.com/digitorus/pdfsign/sign"
)

// Write finalizes the document by executing all staged operations (signatures, form filling, initials).
// It performs incremental updates to the PDF and writes the resulting bytes to the provided writer.
// If multiple signatures were staged, they are applied one after another.
func (d *Document) Write(output io.Writer) (*Result, error) {
	result := &Result{
		Signatures: make([]SignatureInfo, 0, len(d.pendingSigns)),
		Document:   d,
	}

	for _, sb := range d.pendingSigns {
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

		// Execute signing using existing sign package
		// Need to get a ReadSeeker from our reader
		if rs, ok := d.reader.(io.ReadSeeker); ok {
			err := sign.SignWithData(rs, output, d.rdr, d.size, signData)
			if err != nil {
				return nil, err
			}
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
