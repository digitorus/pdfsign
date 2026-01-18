// Package azure provides an Azure Key Vault signer for pdfsign.
//
// NOTE: This package is provided on a "best-effort" basis. It demonstrates
// how to integrate Azure Key Vault with pdfsign but may not cover all
// Azure Key Vault configurations or advanced features.
package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// KMSClient defines the interface for Azure Key Vault operations used by the signer.
type KMSClient interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// Signer implements crypto.Signer using Azure Key Vault.
type Signer struct {
	Client     KMSClient
	KeyName    string
	KeyVersion string // Optional
	PublicKey  crypto.PublicKey
}

// NewSigner creates a new Azure Key Vault signer.
func NewSigner(client KMSClient, keyName string, keyVersion string, pub crypto.PublicKey) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("azure: client is required")
	}
	if keyName == "" {
		return nil, fmt.Errorf("azure: keyName is required")
	}
	return &Signer{
		Client:     client,
		KeyName:    keyName,
		KeyVersion: keyVersion,
		PublicKey:  pub,
	}, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs a digest using Azure Key Vault.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(context.Background(), digest, opts)
}

// SignContext allows passing a context for cloud operations.
func (s *Signer) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo := signingAlgorithm(s.PublicKey, opts.HashFunc())
	if algo == "" {
		return nil, fmt.Errorf("azure: unsupported hash function: %v", opts.HashFunc())
	}

	params := azkeys.SignParameters{
		Algorithm: &algo,
		Value:     digest,
	}

	resp, err := s.Client.Sign(ctx, s.KeyName, s.KeyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: sign failed: %w", err)
	}

	return resp.Result, nil
}

func signingAlgorithm(pub crypto.PublicKey, hash crypto.Hash) azkeys.SignatureAlgorithm {
	switch pub.(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmRS256
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmRS384
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmRS512
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmES256
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmES384
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmES512
		}
	}
	return ""
}
