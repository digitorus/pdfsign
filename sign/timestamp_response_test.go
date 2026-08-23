package sign

import (
	"bytes"
	"crypto"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/timestamp"
)

func TestGetTSAValidatesResponseBinding(t *testing.T) {
	content := []byte("signature value to timestamp")

	tests := []struct {
		name    string
		mutate  func(*timestamp.Request, *timestamp.Timestamp)
		wantErr string
	}{
		{
			name: "Valid",
		},
		{
			name: "WrongHashAlgorithm",
			mutate: func(_ *timestamp.Request, ts *timestamp.Timestamp) {
				ts.HashAlgorithm = crypto.SHA512
				imprint := crypto.SHA512.New()
				_, _ = imprint.Write(content)
				ts.HashedMessage = imprint.Sum(nil)
			},
			wantErr: "hash algorithm SHA-512 does not match requested algorithm SHA-256",
		},
		{
			name: "WrongMessageImprint",
			mutate: func(_ *timestamp.Request, ts *timestamp.Timestamp) {
				ts.HashedMessage = make([]byte, crypto.SHA256.Size())
			},
			wantErr: "message imprint does not match",
		},
		{
			name: "MissingNonce",
			mutate: func(_ *timestamp.Request, ts *timestamp.Timestamp) {
				ts.Nonce = nil
			},
			wantErr: "nonce does not match",
		},
		{
			name: "WrongNonce",
			mutate: func(_ *timestamp.Request, ts *timestamp.Timestamp) {
				ts.Nonce = big.NewInt(1)
			},
			wantErr: "nonce does not match",
		},
		{
			name: "MissingRequestedCertificate",
			mutate: func(_ *timestamp.Request, ts *timestamp.Timestamp) {
				ts.AddTSACertificate = false
			},
			wantErr: "does not include the requested TSA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := &SignContext{SignData: SignData{
				DigestAlgorithm: crypto.SHA256,
				TSA: TSA{
					URL: testpki.StartMockTSAWithResponse(t, tt.mutate),
				},
			}}

			_, err := context.GetTSA(content)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("GetTSA() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("GetTSA() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestGetTSAUsesDefaultHash(t *testing.T) {
	context := &SignContext{SignData: SignData{
		TSA: TSA{URL: testpki.StartMockTSA(t)},
	}}

	if _, err := context.GetTSA([]byte("signature value to timestamp")); err != nil {
		t.Fatalf("GetTSA() error = %v", err)
	}
}

func TestGetTSARejectsOversizedResponse(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "DeclaredContentLength",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "4194305")
				w.WriteHeader(http.StatusOK)
			},
			wantErr: "exceeding the 4194304 byte limit",
		},
		{
			name: "ChunkedBody",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(bytes.Repeat([]byte{'x'}, int(maxTSAResponseSize+1)))
			},
			wantErr: "exceeds the 4194304 byte limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			context := &SignContext{SignData: SignData{
				DigestAlgorithm: crypto.SHA256,
				TSA:             TSA{URL: server.URL},
			}}

			_, err := context.GetTSA([]byte("signature value to timestamp"))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("GetTSA() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
