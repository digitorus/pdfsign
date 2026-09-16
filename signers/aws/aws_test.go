package aws

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type mockKMSClient struct {
	signFunc func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.signFunc(ctx, params, optFns...)
}

func TestSigner_Sign(t *testing.T) {
	mock := &mockKMSClient{
		signFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			if *params.KeyId != "test-key" {
				t.Errorf("expected KeyId 'test-key', got %s", *params.KeyId)
			}
			return &kms.SignOutput{
				Signature: []byte("mock-signature"),
			}, nil
		},
	}

	mockPubKey := &rsa.PublicKey{N: big.NewInt(1), E: 65537}
	signer, err := NewSigner(mock, "test-key", mockPubKey)
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
		signFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, errors.New("kms error")
		},
	}

	signer, _ := NewSigner(mock, "test-key", nil)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
