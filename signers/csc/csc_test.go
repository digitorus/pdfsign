package csc

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSigner_RequiresBaseURL(t *testing.T) {
	_, err := NewSigner(Config{
		CredentialID: "test",
	})
	if err == nil {
		t.Error("expected error for missing BaseURL")
	}
}

func TestNewSigner_RequiresCredentialID(t *testing.T) {
	_, err := NewSigner(Config{
		BaseURL: "https://example.com",
	})
	if err == nil {
		t.Error("expected error for missing CredentialID")
	}
}

func TestSigner_ImplementsCryptoSigner(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"key": {"status": "enabled", "algo": ["1.2.840.113549.1.1.11"], "len": 2048},
			"cert": {"status": "valid", "certificates": []},
			"authMode": "explicit"
		}`))
	}))
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-key",
		AuthToken:    "Bearer test",
	})

	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Verify it implements crypto.Signer
	var _ crypto.Signer = signer
}

func TestHashAlgoName(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want string
	}{
		{crypto.SHA256, "2.16.840.1.101.3.4.2.1"},
		{crypto.SHA384, "2.16.840.1.101.3.4.2.2"},
		{crypto.SHA512, "2.16.840.1.101.3.4.2.3"},
		{crypto.SHA1, "1.3.14.3.2.26"},
		{crypto.MD5, ""}, // Unsupported
	}

	for _, tt := range tests {
		got := hashAlgoName(tt.hash)
		if got != tt.want {
			t.Errorf("hashAlgoName(%v) = %q, want %q", tt.hash, got, tt.want)
		}
	}
}
