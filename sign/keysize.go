package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrNilSigner      = errors.New("signer cannot be nil")
	ErrNilPublicKey   = errors.New("public key cannot be nil")
	ErrNilCertificate = errors.New("certificate cannot be nil")
	ErrUnsupportedKey = errors.New("unsupported key type")
	ErrKeyMismatch    = errors.New("signer public key does not match certificate")
)

// SignatureSize returns the maximum signature size in bytes for the given signer.
// Do not use Certificate.SignatureAlgorithm for this - that's how the CA signed
// the cert, not the size of signatures this key produces.
func SignatureSize(signer crypto.Signer) (int, error) {
	if signer == nil {
		return 0, ErrNilSigner
	}

	pub := signer.Public()
	if pub == nil {
		return 0, ErrNilPublicKey
	}

	return PublicKeySignatureSize(pub)
}

// PublicKeySignatureSize returns the maximum signature size for a public key.
func PublicKeySignatureSize(pub crypto.PublicKey) (int, error) {
	if pub == nil {
		return 0, ErrNilPublicKey
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N == nil {
			return 0, fmt.Errorf("%w: RSA key has nil modulus", ErrUnsupportedKey)
		}
		return k.Size(), nil

	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return 0, fmt.Errorf("%w: ECDSA key has nil curve", ErrUnsupportedKey)
		}
		// ECDSA signatures are DER-encoded as SEQUENCE { r INTEGER, s INTEGER } per RFC 3279 Section 2.2.3.
		// Max size: 2 coords + 9 bytes overhead (SEQUENCE tag/len, two INTEGER tag/len, two padding bytes)
		coordSize := (k.Curve.Params().BitSize + 7) / 8
		return 2*coordSize + 9, nil

	case ed25519.PublicKey:
		return ed25519.SignatureSize, nil

	default:
		return 0, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// DefaultSignatureSize is the fallback for unrecognized key types.
const DefaultSignatureSize = 8192

// ValidateSignerCertificateMatch checks that the signer's public key matches the certificate.
func ValidateSignerCertificateMatch(signer crypto.Signer, cert *x509.Certificate) error {
	if signer == nil {
		return ErrNilSigner
	}
	if cert == nil {
		return ErrNilCertificate
	}

	signerPub := signer.Public()
	if signerPub == nil {
		return ErrNilPublicKey
	}

	signerPubBytes, err := x509.MarshalPKIXPublicKey(signerPub)
	if err != nil {
		return fmt.Errorf("failed to marshal signer public key: %w", err)
	}

	certPubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}

	if len(signerPubBytes) != len(certPubBytes) {
		return ErrKeyMismatch
	}

	for i := range signerPubBytes {
		if signerPubBytes[i] != certPubBytes[i] {
			return ErrKeyMismatch
		}
	}

	return nil
}
