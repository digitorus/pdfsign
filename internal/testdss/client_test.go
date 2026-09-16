package testdss

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClientValidate(t *testing.T) {
	responseBody, err := os.ReadFile("testdata/valid-response.json")
	if err != nil {
		t.Fatal(err)
	}

	documentBytes := []byte("signed PDF bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var request validationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.SignedDocument.Name != "signed.pdf" {
			t.Errorf("document name = %q, want signed.pdf", request.SignedDocument.Name)
		}
		decoded, err := base64.StdEncoding.DecodeString(request.SignedDocument.Bytes)
		if err != nil {
			t.Errorf("decode document bytes: %v", err)
		}
		if string(decoded) != string(documentBytes) {
			t.Errorf("document bytes = %q, want %q", decoded, documentBytes)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(responseBody)
	}))
	defer server.Close()

	client := New(server.URL)
	response, err := client.Validate(context.Background(), "signed.pdf", documentBytes)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	signatures := response.Signatures()
	if len(signatures) != 1 {
		t.Fatalf("signature count = %d, want 1", len(signatures))
	}
	if signatures[0].SignatureFormat != "PAdES-BASELINE-B" {
		t.Errorf("signature format = %q, want PAdES-BASELINE-B", signatures[0].SignatureFormat)
	}
	if signatures[0].Indication != "INDETERMINATE" {
		t.Errorf("indication = %q, want INDETERMINATE", signatures[0].Indication)
	}
}

func TestClientValidateRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantError  string
	}{
		{
			name:       "non-OK status",
			statusCode: http.StatusBadRequest,
			body:       `{"errorMessage":"invalid document"}`,
			wantError:  "status 400",
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `{`,
			wantError:  "decode DSS validation response",
		},
		{
			name:       "zero reported signatures",
			statusCode: http.StatusOK,
			body:       `{"simpleReport":{"signaturesCount":0}}`,
			wantError:  "reports no signatures",
		},
		{
			name:       "reported signature without signature entry",
			statusCode: http.StatusOK,
			body:       `{"simpleReport":{"signaturesCount":1,"signatureOrTimestampOrEvidenceRecord":[{"timestamp":{}}]}}`,
			wantError:  "contains no signature entries",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			_, err := New(server.URL).Validate(context.Background(), "signed.pdf", []byte("document"))
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestClientValidateHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached server after context cancellation")
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := New(server.URL).Validate(ctx, "signed.pdf", []byte("document"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate() error = %v, want context cancellation", err)
	}
}

func TestClientUsesBoundedDefaultTimeout(t *testing.T) {
	client := New("http://example.invalid")
	if client.httpClient.Timeout != defaultHTTPTimeout {
		t.Fatalf("HTTP timeout = %s, want %s", client.httpClient.Timeout, defaultHTTPTimeout)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client = New(server.URL)
	client.httpClient.Timeout = 20 * time.Millisecond
	started := time.Now()
	_, err := client.Validate(context.Background(), "signed.pdf", []byte("document"))
	if err == nil {
		t.Fatal("Validate() error = nil, want timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Validate() took %s, want a bounded timeout", elapsed)
	}
}
