// Package aws provides an AWS KMS signer for pdfsign.
//
// NOTE: This package is provided on a "best-effort" basis. It demonstrates
// how to integrate AWS KMS with pdfsign but may not cover all AWS KMS
// configurations or advanced features.
package aws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClient defines the interface for AWS KMS operations used by the signer.
type KMSClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer implements crypto.Signer using AWS KMS.
type Signer struct {
	Client    KMSClient
	KeyID     string
	PublicKey crypto.PublicKey
}

// NewSigner creates a new AWS KMS signer.
func NewSigner(client KMSClient, keyId string, pub crypto.PublicKey) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("aws: client is required")
	}
	if keyId == "" {
		return nil, fmt.Errorf("aws: keyId is required")
	}
	return &Signer{
		Client:    client,
		KeyID:     keyId,
		PublicKey: pub,
	}, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs a digest using AWS KMS.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(context.Background(), digest, opts)
}

// SignContext signs a digest using AWS KMS with context.
func (s *Signer) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo := signingAlgorithm(s.PublicKey, opts.HashFunc())
	if algo == "" {
		return nil, fmt.Errorf("aws: unsupported signing algorithm or hash function")
	}

	input := &kms.SignInput{
		KeyId:            aws.String(s.KeyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: algo,
	}

	output, err := s.Client.Sign(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws: sign failed: %w", err)
	}

	return output.Signature, nil
}

func signingAlgorithm(pub crypto.PublicKey, hash crypto.Hash) types.SigningAlgorithmSpec {
	switch pub.(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPssSha256
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPssSha384
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPssSha512
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512
		}
	}
	return ""
}
