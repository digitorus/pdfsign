// Package gcp provides a Google Cloud KMS signer for pdfsign.
//
// NOTE: This package is provided on a "best-effort" basis. It demonstrates
// how to integrate Google Cloud KMS with pdfsign but may not cover all
// GCP KMS configurations or advanced features.
package gcp

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// KMSClient defines the interface for GCP KMS operations used by the signer.
type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// Signer implements crypto.Signer using Google Cloud KMS.
type Signer struct {
	Client    KMSClient
	KeyName   string
	PublicKey crypto.PublicKey
}

// NewSigner creates a new GCP KMS signer.
func NewSigner(client KMSClient, keyName string, pub crypto.PublicKey) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("gcp: client is required")
	}
	if keyName == "" {
		return nil, fmt.Errorf("gcp: keyName is required")
	}
	return &Signer{
		Client:    client,
		KeyName:   keyName,
		PublicKey: pub,
	}, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs a digest using GCP KMS.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(context.Background(), digest, opts)
}

// SignContext allows passing a context for cloud operations.
func (s *Signer) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &kmspb.AsymmetricSignRequest{
		Name:   s.KeyName,
		Digest: &kmspb.Digest{},
	}

	// Update digest based on hash function
	switch opts.HashFunc() {
	case crypto.SHA256:
		req.Digest.Digest = &kmspb.Digest_Sha256{Sha256: digest}
	case crypto.SHA384:
		req.Digest.Digest = &kmspb.Digest_Sha384{Sha384: digest}
	case crypto.SHA512:
		req.Digest.Digest = &kmspb.Digest_Sha512{Sha512: digest}
	default:
		return nil, fmt.Errorf("gcp: unsupported hash function: %v", opts.HashFunc())
	}

	resp, err := s.Client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp: sign failed: %w", err)
	}

	return resp.Signature, nil
}
