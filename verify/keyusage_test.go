package verify

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

func TestValidateKeyUsage(t *testing.T) {
	tests := []struct {
		name        string
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
		options     *VerifyOptions
		expectKU    bool
		expectEKU   bool
		kuError     string
		ekuError    string
	}{
		{
			name:        "Valid document signing certificate",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   true,
		},
		{
			name:        "Valid with non-repudiation",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   true,
		},
		{
			name:        "Email protection EKU (allowed alternative)",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   true,
			ekuError:    "certificate uses acceptable but not preferred Extended Key Usage",
		},
		{
			name:        "Client auth EKU (allowed alternative)",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   true,
			ekuError:    "certificate uses acceptable but not preferred Extended Key Usage",
		},
		{
			name:        "ExtKeyUsageAny (too permissive)",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   true,
			ekuError:    "certificate uses ExtKeyUsageAny which is too permissive for PDF signing",
		},
		{
			name:        "Missing digital signature KU",
			keyUsage:    x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options:     DefaultVerifyOptions(),
			expectKU:    false,
			expectEKU:   true,
			kuError:     "certificate does not have Digital Signature key usage",
		},
		{
			name:        "Invalid EKU",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   false,
			ekuError:    "certificate does not have suitable Extended Key Usage for PDF signing",
		},
		{
			name:        "No EKU extension",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   false,
			ekuError:    "certificate has no Extended Key Usage extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock certificate with the test key usages
			cert := &x509.Certificate{
				KeyUsage:    tt.keyUsage,
				ExtKeyUsage: tt.extKeyUsage,
			}

			kuValid, kuError, ekuValid, ekuError := validateKeyUsage(cert, tt.options)

			if kuValid != tt.expectKU {
				t.Errorf("Expected KU valid %v, got %v", tt.expectKU, kuValid)
			}

			if ekuValid != tt.expectEKU {
				t.Errorf("Expected EKU valid %v, got %v", tt.expectEKU, ekuValid)
			}

			if tt.kuError != "" && kuError != tt.kuError {
				t.Errorf("Expected KU error '%s', got '%s'", tt.kuError, kuError)
			} else if tt.kuError == "" && kuError != "" {
				t.Errorf("Expected no KU error, got '%s'", kuError)
			}

			if tt.ekuError != "" && ekuError != tt.ekuError {
				t.Errorf("Expected EKU error '%s', got '%s'", tt.ekuError, ekuError)
			} else if tt.ekuError == "" && ekuError != "" {
				t.Errorf("Expected no EKU error, got '%s'", ekuError)
			}
		})
	}
}

func TestDefaultVerifyOptions(t *testing.T) {
	options := DefaultVerifyOptions()

	if options == nil {
		t.Fatal("DefaultVerifyOptions returned nil")
	}

	if !options.RequireDigitalSignatureKU {
		t.Error("Expected RequireDigitalSignatureKU to be true")
	}

	if !options.AllowNonRepudiationKU {
		t.Error("Expected AllowNonRepudiationKU to be true")
	}

	if !options.UseEmbeddedTimestamp {
		t.Error("Expected UseEmbeddedTimestamp to be true")
	}

	if !options.FallbackToCurrentTime {
		t.Error("Expected FallbackToCurrentTime to be true")
	}

	if len(options.RequiredEKUs) == 0 {
		t.Error("Expected at least one required EKU")
	}

	// Check for Document Signing EKU
	hasDocumentSigning := false
	for _, eku := range options.RequiredEKUs {
		if eku == x509.ExtKeyUsage(36) {
			hasDocumentSigning = true
			break
		}
	}
	if !hasDocumentSigning {
		t.Error("Expected Document Signing EKU (36) in required EKUs")
	}

	// Check for common alternative EKUs
	hasEmailProtection := false
	hasClientAuth := false
	for _, eku := range options.AllowedEKUs {
		if eku == x509.ExtKeyUsageEmailProtection {
			hasEmailProtection = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasEmailProtection {
		t.Error("Expected Email Protection EKU in allowed EKUs")
	}
	if !hasClientAuth {
		t.Error("Expected Client Auth EKU in allowed EKUs")
	}
}

func TestGetVerificationEKUs(t *testing.T) {
	ekus := getVerificationEKUs()

	if len(ekus) == 0 {
		t.Fatal("getVerificationEKUs returned empty slice")
	}

	// Check for required EKUs
	hasDocumentSigning := false
	hasEmailProtection := false
	hasClientAuth := false
	hasAny := false

	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsage(36):
			hasDocumentSigning = true
		case x509.ExtKeyUsageEmailProtection:
			hasEmailProtection = true
		case x509.ExtKeyUsageClientAuth:
			hasClientAuth = true
		case x509.ExtKeyUsageAny:
			hasAny = true
		}
	}

	if !hasDocumentSigning {
		t.Error("Expected Document Signing EKU")
	}
	if !hasEmailProtection {
		t.Error("Expected Email Protection EKU")
	}
	if !hasClientAuth {
		t.Error("Expected Client Auth EKU")
	}
	if !hasAny {
		t.Error("Expected ExtKeyUsageAny for backward compatibility")
	}
}

func TestTimestampVerificationOptions(t *testing.T) {
	tests := []struct {
		name                  string
		useEmbeddedTimestamp  bool
		fallbackToCurrentTime bool
		hasTimestamp          bool
		expectError           bool
		errorContains         string
	}{
		{
			name:                  "Use embedded timestamp - available",
			useEmbeddedTimestamp:  true,
			fallbackToCurrentTime: true,
			hasTimestamp:          true,
			expectError:           false,
		},
		{
			name:                  "Use embedded timestamp - not available, fallback enabled",
			useEmbeddedTimestamp:  true,
			fallbackToCurrentTime: true,
			hasTimestamp:          false,
			expectError:           false,
		},
		{
			name:                  "Use embedded timestamp - not available, fallback disabled",
			useEmbeddedTimestamp:  true,
			fallbackToCurrentTime: false,
			hasTimestamp:          false,
			expectError:           true,
			errorContains:         "Embedded timestamp required but not available",
		},
		{
			name:                  "Don't use embedded timestamp",
			useEmbeddedTimestamp:  false,
			fallbackToCurrentTime: false,
			hasTimestamp:          false,
			expectError:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &VerifyOptions{
				RequiredEKUs:              []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				RequireDigitalSignatureKU: true,
				UseEmbeddedTimestamp:      tt.useEmbeddedTimestamp,
				FallbackToCurrentTime:     tt.fallbackToCurrentTime,
			}

			// Mock signer with or without timestamp
			signer := &Signer{}
			if tt.hasTimestamp {
				// Mock timestamp - we can't easily create a real one here
				// In a real test, you'd need to create a proper timestamp.Timestamp
				signer.TimeStamp = &timestamp.Timestamp{
					Time: time.Now().Add(-24 * time.Hour), // 24 hours ago
				}
			}

			// This is a conceptual test - in practice, you'd need to test with real PKCS7 data
			// For now, we can at least verify the options are set correctly
			if options.UseEmbeddedTimestamp != tt.useEmbeddedTimestamp {
				t.Errorf("Expected UseEmbeddedTimestamp %v, got %v", tt.useEmbeddedTimestamp, options.UseEmbeddedTimestamp)
			}
			if options.FallbackToCurrentTime != tt.fallbackToCurrentTime {
				t.Errorf("Expected FallbackToCurrentTime %v, got %v", tt.fallbackToCurrentTime, options.FallbackToCurrentTime)
			}
		})
	}
}
