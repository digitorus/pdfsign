package azure

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type mockKMSClient struct {
	signFunc func(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

func (m *mockKMSClient) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return m.signFunc(ctx, name, version, parameters, options)
}

func TestSigner_Sign(t *testing.T) {
	mock := &mockKMSClient{
		signFunc: func(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
			if name != "test-key" {
				t.Errorf("expected KeyName 'test-key', got %s", name)
			}
			return azkeys.SignResponse{
				KeyOperationResult: azkeys.KeyOperationResult{
					Result: []byte("mock-signature"),
				},
			}, nil
		},
	}

	mockPubKey := &rsa.PublicKey{N: big.NewInt(1), E: 65537}
	signer, err := NewSigner(mock, "test-key", "", mockPubKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	sig, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if string(sig) != "mock-signature" {
		t.Errorf("expected signature 'mock-signature', got %s", string(sig))
	}
}

func TestSigner_Sign_Error(t *testing.T) {
	mock := &mockKMSClient{
		signFunc: func(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
			return azkeys.SignResponse{}, errors.New("kms error")
		},
	}

	signer, _ := NewSigner(mock, "test-key", "", nil)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
