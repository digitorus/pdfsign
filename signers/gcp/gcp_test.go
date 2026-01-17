package gcp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

type mockKMSClient struct {
	asymmetricSignFunc func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

func (m *mockKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	return m.asymmetricSignFunc(ctx, req, opts...)
}

func TestSigner_Sign(t *testing.T) {
	mock := &mockKMSClient{
		asymmetricSignFunc: func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			if req.Name != "test-key" {
				t.Errorf("expected KeyName 'test-key', got %s", req.Name)
			}
			return &kmspb.AsymmetricSignResponse{
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
		asymmetricSignFunc: func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			return nil, errors.New("kms error")
		},
	}

	signer, _ := NewSigner(mock, "test-key", nil)
	_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
