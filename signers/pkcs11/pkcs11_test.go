package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestNewSigner(t *testing.T) {
	_, err := NewSigner("", "token", "key", "pin", nil)
	if err == nil {
		t.Error("expected error for missing module path")
	}

	mockPubKey := &rsa.PublicKey{N: big.NewInt(1), E: 65537}
	signer, err := NewSigner("module.so", "token", "key", "pin", mockPubKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.ModulePath != "module.so" {
		t.Errorf("expected ModulePath 'module.so', got %s", signer.ModulePath)
	}
}

func TestSigner_Public(t *testing.T) {
	pub := &struct{ crypto.PublicKey }{}
	signer, _ := NewSigner("module.so", "token", "key", "pin", pub)
	if signer.Public() != pub {
		t.Error("Public() did not return the expected public key")
	}
}

// Note: Structural tests for Sign() would require a mock PKCS#11 library (e.g. SoftHSM)
// or a mock of the pkcs11.Ctx interface. For "best-effort" examples, we focus
// on the structural initialization here. The encoding helpers below (which
// bridge CKM_RSA_PKCS/CKM_ECDSA's raw mechanism semantics to what a
// crypto.Signer must return) are pure functions and are tested directly.

func TestDigestInfoPrefix(t *testing.T) {
	// A CKM_RSA_PKCS mechanism performs only the raw RSA private-key
	// operation with PKCS#1 v1.5 padding; it has no notion of "signing a
	// SHA-256 digest" the way rsa.SignPKCS1v15 does; the DigestInfo prefix
	// must already be baked into the padded message. We verify that a raw
	// RSA private-key operation over (prefix || digest), padded exactly as
	// PKCS#1 v1.5 would, produces a signature that crypto/rsa.VerifyPKCS1v15
	// accepts for that hash -- proving the prefix matches what crypto/rsa
	// itself builds internally for the same hash algorithm.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		prefix, err := digestInfoPrefix(hash)
		if err != nil {
			t.Fatalf("digestInfoPrefix(%v): %v", hash, err)
		}
		digest := make([]byte, hash.Size())
		if _, err := rand.Read(digest); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		digestInfo := append(prefix, digest...)

		padded, err := pkcs1v15Pad(digestInfo, key.Size())
		if err != nil {
			t.Fatalf("pkcs1v15Pad: %v", err)
		}

		c := new(big.Int).SetBytes(padded)
		sigInt := new(big.Int).Exp(c, key.D, key.N)
		sig := make([]byte, key.Size())
		sigInt.FillBytes(sig)

		if err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, sig); err != nil {
			t.Fatalf("VerifyPKCS1v15 rejected signature built with our DigestInfo prefix for %v: %v", hash, err)
		}
	}

	if _, err := digestInfoPrefix(crypto.MD5); err == nil {
		t.Error("expected error for unsupported hash algorithm")
	}
}

// pkcs1v15Pad applies EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2) to msg for a
// modulus of the given byte size, emulating what an HSM's CKM_RSA_PKCS
// mechanism does internally before the raw RSA private-key operation.
func pkcs1v15Pad(msg []byte, k int) ([]byte, error) {
	if k < len(msg)+11 {
		return nil, fmt.Errorf("message too long")
	}
	padded := make([]byte, k)
	padded[1] = 0x01
	padLen := k - len(msg) - 3
	for i := 0; i < padLen; i++ {
		padded[2+i] = 0xff
	}
	copy(padded[k-len(msg):], msg)
	return padded, nil
}

func TestEcdsaRawToASN1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("test message"))

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}

	coordSize := 32
	raw := make([]byte, 2*coordSize)
	r.FillBytes(raw[:coordSize])
	s.FillBytes(raw[coordSize:])

	der, err := ecdsaRawToASN1(raw, 256)
	if err != nil {
		t.Fatalf("ecdsaRawToASN1: %v", err)
	}

	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Error("ecdsa.VerifyASN1 rejected the converted signature")
	}

	if _, err := ecdsaRawToASN1(raw[:len(raw)-1], 256); err == nil {
		t.Error("expected error for wrong-length raw signature")
	}
}
