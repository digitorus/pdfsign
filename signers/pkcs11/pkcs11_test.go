package pkcs11

import (
	"crypto"
	"crypto/rsa"
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
// on the structural initialization here.
