// Package pkcs11 provides a PKCS#11 (HSM/Token) signer for pdfsign.
//
// NOTE: This package is provided on a "best-effort" basis. It demonstrates
// how to integrate hardware security modules with pdfsign but may not cover
// all PKCS#11 module variations or advanced features.
package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

// Signer implements crypto.Signer using a PKCS#11 module (HSM/Token).
type Signer struct {
	ModulePath string
	TokenLabel string
	KeyLabel   string
	PIN        string
	PublicKey  crypto.PublicKey
}

// NewSigner creates a new PKCS#11 signer.
func NewSigner(module, token, key, pin string, pub crypto.PublicKey) (*Signer, error) {
	if module == "" {
		return nil, fmt.Errorf("pkcs11: ModulePath is required")
	}
	return &Signer{
		ModulePath: module,
		TokenLabel: token,
		KeyLabel:   key,
		PIN:        pin,
		PublicKey:  pub,
	}, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs a digest using the PKCS#11 module.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	p := pkcs11.New(s.ModulePath)
	if p == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %s", s.ModulePath)
	}

	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: error initializing module: %w", err)
	}
	defer func() {
		_ = p.Finalize()
		p.Destroy()
	}()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error getting slots: %w", err)
	}

	var slotID uint
	foundSlot := false
	for _, sID := range slots {
		tokenInfo, err := p.GetTokenInfo(sID)
		if err != nil {
			continue
		}
		if tokenInfo.Label == s.TokenLabel || s.TokenLabel == "" {
			slotID = sID
			foundSlot = true
			break
		}
	}

	if !foundSlot {
		return nil, fmt.Errorf("pkcs11: token with label %q not found", s.TokenLabel)
	}

	session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error opening session: %w", err)
	}
	defer func() { _ = p.CloseSession(session) }()

	if s.PIN != "" {
		if err := p.Login(session, pkcs11.CKU_USER, s.PIN); err != nil {
			return nil, fmt.Errorf("pkcs11: error logging in: %w", err)
		}
		defer func() { _ = p.Logout(session) }()
	}

	// Find the private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if s.KeyLabel != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, s.KeyLabel))
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("pkcs11: error finding objects: %w", err)
	}

	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error finding objects: %w", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("pkcs11: error finalizing object find: %w", err)
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("pkcs11: private key not found")
	}
	privKey := objs[0]

	mechanism := getMechanism(s.PublicKey, opts.HashFunc())
	if mechanism == nil {
		return nil, fmt.Errorf("pkcs11: unsupported public key or hash function")
	}

	if err := p.SignInit(session, []*pkcs11.Mechanism{mechanism}, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11: sign init failed: %w", err)
	}

	// CKM_RSA_PKCS performs only the raw RSA private-key operation with
	// PKCS#1 v1.5 padding; unlike crypto/rsa.SignPKCS1v15, it does not know
	// which hash algorithm produced the digest, so the DER-encoded
	// DigestInfo prefix (RFC 8017 §9.2) must be prepended by the caller.
	signInput := digest
	if _, isRSA := s.PublicKey.(*rsa.PublicKey); isRSA {
		prefix, err := digestInfoPrefix(opts.HashFunc())
		if err != nil {
			return nil, fmt.Errorf("pkcs11: %w", err)
		}
		signInput = append(prefix, digest...)
	}

	sig, err := p.Sign(session, signInput)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign failed: %w", err)
	}

	// CKM_ECDSA returns the raw, fixed-width concatenation r || s, but
	// crypto.Signer implementations (and downstream consumers such as
	// crypto/x509 and pkcs7) expect the ASN.1 DER SEQUENCE{r, s} encoding
	// that crypto/ecdsa.Sign produces.
	if ecKey, isECDSA := s.PublicKey.(*ecdsa.PublicKey); isECDSA {
		return ecdsaRawToASN1(sig, ecKey.Curve.Params().BitSize)
	}

	return sig, nil
}

func getMechanism(pub crypto.PublicKey, hash crypto.Hash) *pkcs11.Mechanism {
	switch pub.(type) {
	case *rsa.PublicKey:
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	case *ecdsa.PublicKey:
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		// Fallback to RSA PKCS for backward compatibility or generic keys
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	}
}

// digestInfoPrefix returns the DER encoding of the DigestAlgorithm portion of
// a PKCS#1 DigestInfo structure (RFC 8017 §9.2, Note 1) for hash, i.e.
// everything except the digest bytes themselves.
func digestInfoPrefix(hash crypto.Hash) ([]byte, error) {
	switch hash {
	case crypto.SHA1:
		return []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}, nil
	case crypto.SHA256:
		return []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, nil
	case crypto.SHA384:
		return []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}, nil
	case crypto.SHA512:
		return []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm for CKM_RSA_PKCS: %v", hash)
	}
}

// ecdsaRawToASN1 converts the raw, fixed-width r||s signature CKM_ECDSA
// returns into the ASN.1 DER SEQUENCE{r, s} encoding crypto.Signer callers
// expect. curveBits is the signing curve's field size (e.g. 256 for P-256).
func ecdsaRawToASN1(raw []byte, curveBits int) ([]byte, error) {
	coordSize := (curveBits + 7) / 8
	if len(raw) != 2*coordSize {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d, want %d", len(raw), 2*coordSize)
	}

	r := new(big.Int).SetBytes(raw[:coordSize])
	s := new(big.Int).SetBytes(raw[coordSize:])

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}
