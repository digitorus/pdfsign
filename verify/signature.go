package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	"crypto/sha256"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/subnoto/pdfsign/common"
	"github.com/subnoto/pdfsign/revocation"
)

// processSignature processes a single digital signature found in the PDF.
func processSignature(v pdf.Value, file io.ReaderAt, options *VerifyOptions) (common.SignatureInfo, SignatureValidation, string, error) {
	info := common.SignatureInfo{
		Name:        v.Key("Name").Text(),
		Reason:      v.Key("Reason").Text(),
		Location:    v.Key("Location").Text(),
		ContactInfo: v.Key("ContactInfo").Text(),
	}

	// Parse signature time if available from the signature object
	sigTime := v.Key("M")
	if !sigTime.IsNull() {
		if t, err := parseDate(sigTime.Text()); err == nil {
			info.SignatureTime = &t
		}
	}

	info.HashAlgorithm = "sha256" // default

	// Parse PKCS#7 signature
	p7, err := pkcs7.Parse([]byte(v.Key("Contents").RawString()))
	if err != nil {
		return info, SignatureValidation{}, "", fmt.Errorf("failed to parse PKCS#7: %v", err)
	}

	// Process byte range for signature verification
	err = processByteRange(v, file, p7)
	if err != nil {
		return info, SignatureValidation{}, fmt.Sprintf("Failed to process ByteRange: %v", err), nil
	}

	// Calculate document hash (SHA256 by default)
	// (Assume the byte range covers the signed content)
	// You may want to expose the hash algorithm in options for flexibility
	h := sha256.New()
	h.Write(p7.Content)
	info.DocumentHash = fmt.Sprintf("%x", h.Sum(nil))

	// Calculate signature hash (SHA256 by default)
	h.Reset()
	h.Write([]byte(v.Key("Contents").RawString()))
	info.SignatureHash = fmt.Sprintf("%x", h.Sum(nil))

	// Process timestamp if present
	err = processTimestamp(p7, &info)
	if err != nil {
		return info, SignatureValidation{}, fmt.Sprintf("Failed to process timestamp: %v", err), nil
	}

	// Verify the digital signature
	var validation SignatureValidation
	err = verifySignature(p7, &validation)
	if err != nil {
		return info, validation, fmt.Sprintf("Failed to verify signature: %v", err), nil
	}

	// Process certificate chains and revocation
	var revInfo revocation.InfoArchival
	_ = p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, &revInfo)

	certError, err := buildCertificateChainsWithOptions(p7, &info, &validation, revInfo, options)
	if err != nil {
		return info, validation, fmt.Sprintf("Failed to build certificate chains: %v", err), nil
	}

	return info, validation, certError, nil
}

// processByteRange processes the byte range for signature verification.
func processByteRange(v pdf.Value, file io.ReaderAt, p7 *pkcs7.PKCS7) error {
	for i := 0; i < v.Key("ByteRange").Len(); i++ {
		// As the byte range comes in pairs, we increment one extra
		i++

		// Read the byte range from the raw file and add it to the contents.
		// This content will be hashed with the corresponding algorithm to
		// verify the signature.
		content, err := io.ReadAll(io.NewSectionReader(file, v.Key("ByteRange").Index(i-1).Int64(), v.Key("ByteRange").Index(i).Int64()))
		if err != nil {
			return fmt.Errorf("failed to read byte range %d: %v", i, err)
		}

		p7.Content = append(p7.Content, content...)
	}
	return nil
}

// processTimestamp processes timestamp information from the signature.
func processTimestamp(p7 *pkcs7.PKCS7, signer *common.SignatureInfo) error {
	for _, s := range p7.Signers {
		// Timestamp - RFC 3161 id-aa-timeStampToken
		for _, attr := range s.UnauthenticatedAttributes {
			if attr.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}) {
				ts, err := timestamp.Parse(attr.Value.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse timestamp: %v", err)
				}

				signer.TimeStamp = ts

				// Verify timestamp hash
				r := bytes.NewReader(s.EncryptedDigest)
				h := signer.TimeStamp.HashAlgorithm.New()
				b := make([]byte, h.Size())
				for {
					n, err := r.Read(b)
					if err == io.EOF {
						break
					}
					h.Write(b[:n])
				}

				if !bytes.Equal(h.Sum(nil), signer.TimeStamp.HashedMessage) {
					return fmt.Errorf("timestamp hash does not match")
				}
				break
			}
		}
	}
	return nil
}

// verifySignature verifies the digital signature.
func verifySignature(p7 *pkcs7.PKCS7, validation *SignatureValidation) error {
	// Directory of certificates, including OCSP
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Verify the digital signature of the pdf file.
	err := p7.VerifyWithChain(certPool)
	if err != nil {
		err = p7.Verify()
		if err == nil {
			validation.ValidSignature = true
			validation.TrustedIssuer = false
		} else {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	} else {
		validation.ValidSignature = true
		validation.TrustedIssuer = true
	}

	return nil
}
