package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// VerifySignature processes a single digital signature found in the PDF.
func VerifySignature(v pdf.Value, file io.ReaderAt, fileSize int64, options *VerifyOptions) (*Signer, error) {
	signer := NewSigner()
	signer.Name = v.Key("Name").Text()
	signer.Reason = v.Key("Reason").Text()
	signer.Location = v.Key("Location").Text()
	signer.ContactInfo = v.Key("ContactInfo").Text()

	// Check for DocMDP and incremental updates
	if err := checkDocMDP(v, fileSize, signer); err != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("DocMDP validation failed: %v", err)})
		return signer, nil
	}

	// Parse signature time if available from the signature object
	sigTime := v.Key("M")
	if !sigTime.IsNull() {
		if t, err := parseDate(sigTime.Text()); err == nil {
			signer.SignatureTime = &t
		}
	}

	// Parse PKCS#7 signature
	rawSignature := []byte(v.Key("Contents").RawString())
	p7, err := pkcs7.Parse(rawSignature)
	if err != nil {
		return signer, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	isDocTimeStamp := (v.Key("SubFilter").Name() == "ETSI.RFC3161")

	if isDocTimeStamp {
		// DocTimeStamp: p7.Content contains the TSTInfo (embedded).
		// We verify the PDF bytes match the TSTInfo MessageImprint.
		pdfBytes, err := readByteRange(v, file)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to read ByteRange: %v", err)})
			return signer, nil
		}

		// Parse TSTInfo to check MessageImprint.
		// We parse the original token because timestamp.Parse expects ContentInfo,
		// whereas p7.Content is the inner TSTInfo.
		ts, err := timestamp.Parse(rawSignature)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to parse TSTInfo: %v", err)})
			return signer, nil
		}
		signer.TimeStamp = ts

		// Verify hash of PDF bytes vs MessageImprint
		h := ts.HashAlgorithm.New()
		h.Write(pdfBytes)
		if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: "timestamp hash does not match"})
			return signer, nil
		}

		// Verify reference to the previous signature (if available).
		// For a DocTimeStamp, if there are previous signatures, the ByteRange
		// covers them. So the hash check above implicitly validates the integrity
		// of the previous state.

		// Verify the TSTInfo signature (standard verification on embedded content)
		// We skip processTimestamp as the timestamp IS the content, not an attribute.
		err = verifySignature(p7, signer)
		if err != nil {
			// Specific error for DocTimeStamp
			signer.ValidationErrors = append(signer.ValidationErrors, &InvalidSignatureError{Msg: fmt.Sprintf("Failed to verify timestamp signature: %v", err)})
			return signer, nil
		}

	} else {
		// Standard Detached Signature
		// Process byte range uses the PDF content as the signed data
		err = processByteRange(v, file, p7)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process ByteRange: %v", err)})
			return signer, nil
		}

		// Process timestamp if present (as an attribute)
		err = processTimestamp(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process timestamp: %v", err)})
			return signer, nil
		}

		// Verify the digital signature
		err = verifySignature(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &InvalidSignatureError{Msg: fmt.Sprintf("Failed to verify signature: %v", err)})
			return signer, nil
		}
	}

	// Process certificate chains and revocation
	var revInfo revocation.InfoArchival
	_ = p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, &revInfo)

	certError, err := buildCertificateChainsWithOptions(p7, signer, revInfo, options)
	if err != nil {
		// This means critical failure in chain building (e.g. malformed certs that crash x509)
		return signer, fmt.Errorf("failed to build certificate chains: %w", err)
	}
	if certError != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, certError)
	}

	// Check algorithm constraints
	if algoErr := verifyAlgorithmAndKeySize(signer, p7, options); algoErr != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, &PolicyError{Msg: fmt.Sprintf("Algorithm verification failed: %v", algoErr)})
		return signer, nil
	}

	return signer, nil
}

func verifyAlgorithmAndKeySize(signer *Signer, p7 *pkcs7.PKCS7, options *VerifyOptions) error {
	if len(signer.Certificates) == 0 {
		return nil
	}

	// Helper to verify a single certificate
	verifyCert := func(cert *x509.Certificate, isLeaf bool) error {
		if cert == nil {
			return nil
		}

		// 1. Verify Allowed Algorithms
		if len(options.AllowedAlgorithms) > 0 {
			allowed := false
			for _, algo := range options.AllowedAlgorithms {
				if cert.PublicKeyAlgorithm == algo {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("public key algorithm %s is not allowed (isLeaf: %v)", cert.PublicKeyAlgorithm, isLeaf)
			}
		}

		// 2. Verify Minimum Key Size
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if options.MinRSAKeySize > 0 && pub.N.BitLen() < options.MinRSAKeySize {
				return fmt.Errorf("RSA key size %d is less than minimum %d (isLeaf: %v)", pub.N.BitLen(), options.MinRSAKeySize, isLeaf)
			}
		case *ecdsa.PublicKey:
			if options.MinECDSAKeySize > 0 && pub.Params().BitSize < options.MinECDSAKeySize {
				return fmt.Errorf("ECDSA key size %d is less than minimum %d (isLeaf: %v)", pub.Params().BitSize, options.MinECDSAKeySize, isLeaf)
			}
		}
		return nil
	}

	// Identify the leaf signer
	// We try to match the signer info from p7
	var leafCert *x509.Certificate
	if len(p7.Signers) > 0 {
		signerInfo := p7.Signers[0]
		for _, cert := range p7.Certificates {
			// Compare Serial Number
			if cert.SerialNumber.Cmp(signerInfo.IssuerAndSerialNumber.SerialNumber) == 0 {
				// Compare Issuer (Raw Bytes)
				// signerInfo.IssuerAndSerialNumber.IssuerName is asn1.RawValue
				if bytes.Equal(cert.RawIssuer, signerInfo.IssuerAndSerialNumber.IssuerName.FullBytes) {
					leafCert = cert
					break
				}
			}
		}
	}
	// Fallback if not found (e.g. strict matching fail), assume first in list if single
	if leafCert == nil && len(p7.Certificates) > 0 {
		leafCert = p7.Certificates[0]
	}

	if options.ValidateFullChain {
		// Verify all certificates
		for _, certWrapper := range signer.Certificates {
			isLeaf := (certWrapper.Certificate == leafCert)
			if err := verifyCert(certWrapper.Certificate, isLeaf); err != nil {
				return err
			}
		}
	} else {
		// Only verify the leaf
		if leafCert != nil {
			if err := verifyCert(leafCert, true); err != nil {
				return err
			}
		}
	}

	return nil
}

// processByteRange processes the byte range for signature verification.
func processByteRange(v pdf.Value, file io.ReaderAt, p7 *pkcs7.PKCS7) error {
	content, err := readByteRange(v, file)
	if err != nil {
		return err
	}
	p7.Content = content
	return nil
}

// readByteRange reads the content defined by ByteRange.
func readByteRange(v pdf.Value, file io.ReaderAt) ([]byte, error) {
	var parts []io.Reader
	var totalSize int64

	br := v.Key("ByteRange")
	if br.Len()%2 != 0 {
		return nil, fmt.Errorf("invalid ByteRange length: %d", br.Len())
	}

	for i := 0; i < br.Len(); i += 2 {
		offset := br.Index(i).Int64()
		length := br.Index(i + 1).Int64()

		parts = append(parts, io.NewSectionReader(file, offset, length))
		totalSize += length
	}

	// Pre-allocate the content buffer
	content := make([]byte, totalSize)

	// Use MultiReader to treat the separate ranges as a single continuous stream
	reader := io.MultiReader(parts...)

	_, err := io.ReadFull(reader, content)
	if err != nil {
		return nil, fmt.Errorf("failed to read signed content: %v", err)
	}

	return content, nil
}

// processTimestamp processes timestamp information from the signature.
func processTimestamp(p7 *pkcs7.PKCS7, signer *Signer) error {
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
func verifySignature(p7 *pkcs7.PKCS7, signer *Signer) error {
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
			signer.ValidSignature = true
			signer.TrustedIssuer = false
		} else {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	} else {
		signer.ValidSignature = true
		signer.TrustedIssuer = true
	}

	return nil
}

// checkDocMDP verifies Document Modification Detection and Prevention permissions.
func checkDocMDP(v pdf.Value, fileSize int64, signer *Signer) error {
	refs := v.Key("Reference")
	if refs.IsNull() || refs.Kind() != pdf.Array {
		return nil
	}

	for i := 0; i < refs.Len(); i++ {
		ref := refs.Index(i)
		transform := ref.Key("TransformMethod")
		if transform.Name() == "DocMDP" {
			// Found DocMDP
			perms := 2 // Default
			params := ref.Key("TransformParams")
			if !params.IsNull() {
				p := params.Key("P")
				if !p.IsNull() {
					perms = int(p.Int64())
				}
			}

			// Check for incremental updates
			br := v.Key("ByteRange")
			if br.Len() < 4 {
				return nil // Should fail elsewhere if ByteRange is bad
			}

			// End of the signed range
			signedEnd := br.Index(2).Int64() + br.Index(3).Int64()

			// Detect if there are modifications (bytes appended)
			if fileSize > signedEnd {
				// We have an incremental update

				// P=1: No changes permitted
				if perms == 1 {
					// Strictly invalid
					return fmt.Errorf("incremental update found but P=1 (NoChanges) permits none")
				}

				// P=2: Form filling permitted
				if perms == 2 {
					// TODO: validate that the update only contains form moves/values or signature.
					signer.TimeWarnings = append(signer.TimeWarnings, "DocMDP P=2: Incremental update found (content verification skipped)")
				}

				// P=3: Annotations permitted
				if perms == 3 {
					// TODO: validate annotations
					signer.TimeWarnings = append(signer.TimeWarnings, "DocMDP P=3: Incremental update found (content verification skipped)")
				}
			}
		}
	}
	return nil
}
