// Package csc provides a Cloud Signature Consortium (CSC) API client
// that implements crypto.Signer for remote signing.
//
// This package implements the CSC API v2 specification, which is the
// current standard for cloud-based digital signatures. It should be
// compatible with CSC v1.0.4, v2.0, v2.1, and v2.2 compliant services.
//
// Usage:
//
//	signer, _ := csc.NewSigner(csc.Config{
//	    BaseURL:      "https://signing-service.example.com/csc/v1",
//	    CredentialID: "my-signing-key",
//	    AuthToken:    "Bearer ey...",
//	})
//
//	doc.Sign(signer, cert).
//	    Reason("Approved").
//	    Write(output)
//
// See https://cloudsignatureconsortium.org/ for the CSC API specification.
package csc

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Config configures the CSC signer.
type Config struct {
	// BaseURL is the CSC API base URL (e.g., "https://example.com/csc/v1")
	BaseURL string

	// CredentialID is the ID of the signing credential
	CredentialID string

	// AuthToken is the authorization token (e.g., "Bearer token...")
	AuthToken string

	// PIN is the optional PIN for credential authorization
	PIN string

	// OTP is the optional one-time password
	OTP string

	// HTTPClient is an optional custom HTTP client
	HTTPClient *http.Client
}

// Signer implements crypto.Signer using the CSC API.
type Signer struct {
	config     Config
	publicKey  crypto.PublicKey
	signAlgo   string
	httpClient *http.Client
}

// NewSigner creates a new CSC signer.
// It fetches credential info to determine the public key and supported algorithms.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("csc: BaseURL is required")
	}
	if cfg.CredentialID == "" {
		return nil, fmt.Errorf("csc: CredentialID is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	s := new(Signer)
	s.config = cfg
	s.httpClient = client

	// Fetch credential info
	if err := s.fetchCredentialInfo(); err != nil {
		return nil, fmt.Errorf("csc: failed to fetch credential info: %w", err)
	}

	return s, nil
}

// credentialInfoRequest is the request body for credentials/info
type credentialInfoRequest struct {
	CredentialID string `json:"credentialID"`
}

// credentialInfoResponse is the response from credentials/info
type credentialInfoResponse struct {
	Key struct {
		Status string   `json:"status"`
		Algo   []string `json:"algo"`
		Len    int      `json:"len"`
	} `json:"key"`
	Cert struct {
		Status       string   `json:"status"`
		Certificates []string `json:"certificates"`
	} `json:"cert"`
	AuthMode string `json:"authMode"`
}

// fetchCredentialInfo retrieves the credential information from the CSC service.
func (s *Signer) fetchCredentialInfo() error {
	reqBody := credentialInfoRequest{
		CredentialID: s.config.CredentialID,
	}

	respBody, err := s.doRequest("credentials/info", reqBody)
	if err != nil {
		return err
	}

	var info credentialInfoResponse
	if err := json.Unmarshal(respBody, &info); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract public key from first certificate
	if len(info.Cert.Certificates) > 0 {
		certDER, err := base64.StdEncoding.DecodeString(info.Cert.Certificates[0])
		if err != nil {
			return fmt.Errorf("failed to decode certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		s.publicKey = cert.PublicKey
	}

	// Select best signing algorithm
	if len(info.Key.Algo) > 0 {
		s.signAlgo = info.Key.Algo[0]
	}

	return nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// signHashRequest is the request body for signatures/signHash
type signHashRequest struct {
	CredentialID string   `json:"credentialID"`
	SAD          string   `json:"SAD,omitempty"`
	Hashes       []string `json:"hash"`
	HashAlgo     string   `json:"hashAlgo"`
	SignAlgo     string   `json:"signAlgo"`
}

// signHashResponse is the response from signatures/signHash
type signHashResponse struct {
	Signatures []string `json:"signatures"`
}

// Sign signs the digest using the CSC API.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Determine hash algorithm name
	hashAlgo := hashAlgoName(opts.HashFunc())
	if hashAlgo == "" {
		return nil, fmt.Errorf("csc: unsupported hash algorithm: %v", opts.HashFunc())
	}

	// Authorize credential if needed (get SAD - Signature Activation Data)
	sad, err := s.authorizeCredential()
	if err != nil {
		return nil, fmt.Errorf("csc: failed to authorize credential: %w", err)
	}

	// Create sign request
	req := signHashRequest{
		CredentialID: s.config.CredentialID,
		SAD:          sad,
		Hashes:       []string{base64.StdEncoding.EncodeToString(digest)},
		HashAlgo:     hashAlgo,
		SignAlgo:     s.signAlgo,
	}

	respBody, err := s.doRequest("signatures/signHash", req)
	if err != nil {
		return nil, fmt.Errorf("csc: sign request failed: %w", err)
	}

	var resp signHashResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("csc: failed to parse sign response: %w", err)
	}

	if len(resp.Signatures) == 0 {
		return nil, fmt.Errorf("csc: no signatures returned")
	}

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(resp.Signatures[0])
	if err != nil {
		return nil, fmt.Errorf("csc: failed to decode signature: %w", err)
	}

	return sig, nil
}

// authorizeCredentialRequest is the request for credentials/authorize
type authorizeCredentialRequest struct {
	CredentialID  string `json:"credentialID"`
	NumSignatures int    `json:"numSignatures"`
	PIN           string `json:"PIN,omitempty"`
	OTP           string `json:"OTP,omitempty"`
}

// authorizeCredentialResponse is the response from credentials/authorize
type authorizeCredentialResponse struct {
	SAD string `json:"SAD"`
}

// authorizeCredential gets the Signature Activation Data (SAD).
func (s *Signer) authorizeCredential() (string, error) {
	req := authorizeCredentialRequest{
		CredentialID:  s.config.CredentialID,
		NumSignatures: 1,
		PIN:           s.config.PIN,
		OTP:           s.config.OTP,
	}

	respBody, err := s.doRequest("credentials/authorize", req)
	if err != nil {
		// Some services don't require authorization
		return "", nil
	}

	var resp authorizeCredentialResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", nil
	}

	return resp.SAD, nil
}

// doRequest performs an HTTP POST request to the CSC API.
func (s *Signer) doRequest(endpoint string, body interface{}) ([]byte, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := s.config.BaseURL + "/" + endpoint
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.AuthToken != "" {
		req.Header.Set("Authorization", s.config.AuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// hashAlgoName converts crypto.Hash to CSC algorithm name
func hashAlgoName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "2.16.840.1.101.3.4.2.1" // OID for SHA-256
	case crypto.SHA384:
		return "2.16.840.1.101.3.4.2.2" // OID for SHA-384
	case crypto.SHA512:
		return "2.16.840.1.101.3.4.2.3" // OID for SHA-512
	case crypto.SHA1:
		return "1.3.14.3.2.26" // OID for SHA-1
	default:
		return ""
	}
}
