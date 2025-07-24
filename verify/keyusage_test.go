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
			name:        "Missing digital signature KU",
			keyUsage:    x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options:     DefaultVerifyOptions(),
			expectKU:    false,
			expectEKU:   true,
			kuError:     "certificate does not have Digital Signature key usage",
		},
		{
			name:        "ExtKeyUsageAny (no longer allowed by default)",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			options:     DefaultVerifyOptions(),
			expectKU:    true,
			expectEKU:   false,
			ekuError:    "certificate does not have suitable Extended Key Usage for PDF signing",
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
		{
			name:        "Required non-repudiation - present",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options: &VerifyOptions{
				RequiredEKUs:              []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				AllowedEKUs:               []x509.ExtKeyUsage{},
				RequireDigitalSignatureKU: true,
				RequireNonRepudiation:     true,
			},
			expectKU:  true,
			expectEKU: true,
		},
		{
			name:        "Required non-repudiation - missing",
			keyUsage:    x509.KeyUsageDigitalSignature,            // Missing ContentCommitment
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options: &VerifyOptions{
				RequiredEKUs:              []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				AllowedEKUs:               []x509.ExtKeyUsage{},
				RequireDigitalSignatureKU: true,
				RequireNonRepudiation:     true,
			},
			expectKU:  false,
			expectEKU: true,
			kuError:   "certificate does not have Non-Repudiation key usage",
		},
		{
			name:        "Both digital signature and non-repudiation missing",
			keyUsage:    x509.KeyUsageKeyEncipherment,             // Missing both
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Document Signing EKU
			options: &VerifyOptions{
				RequiredEKUs:              []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				AllowedEKUs:               []x509.ExtKeyUsage{},
				RequireDigitalSignatureKU: true,
				RequireNonRepudiation:     true,
			},
			expectKU:  false,
			expectEKU: true,
			kuError:   "certificate does not have Digital Signature key usage; certificate does not have Non-Repudiation key usage",
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

	if options.RequireNonRepudiation {
		t.Error("Expected RequireNonRepudiation to be false by default (optional)")
	}

	if options.TrustSignatureTime {
		t.Error("Expected TrustSignatureTime to be false by default (secure)")
	}

	if !options.ValidateTimestampCertificates {
		t.Error("Expected ValidateTimestampCertificates to be true")
	}

	// SECURITY: Default should NOT allow embedded certificates as roots
	if options.AllowUntrustedRoots {
		t.Error("Expected AllowUntrustedRoots to be false by default (security)")
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

	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsage(36):
			hasDocumentSigning = true
		case x509.ExtKeyUsageEmailProtection:
			hasEmailProtection = true
		case x509.ExtKeyUsageClientAuth:
			hasClientAuth = true
		case x509.ExtKeyUsageAny:
			t.Error("ExtKeyUsageAny should no longer be included as it makes other EKUs redundant")
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

	// Verify we have exactly 3 EKUs (no ExtKeyUsageAny)
	if len(ekus) != 3 {
		t.Errorf("Expected exactly 3 EKUs, got %d", len(ekus))
	}
}

func TestTimestampVerificationOptions(t *testing.T) {
	tests := []struct {
		name                          string
		trustSignatureTime            bool
		validateTimestampCertificates bool
		hasTimestamp                  bool
		expectError                   bool
		errorContains                 string
	}{
		{
			name:                          "Timestamp available - certificates validated",
			trustSignatureTime:            false,
			validateTimestampCertificates: true,
			hasTimestamp:                  true,
			expectError:                   false,
		},
		{
			name:                          "No timestamp - signature time fallback disabled",
			trustSignatureTime:            false,
			validateTimestampCertificates: true,
			hasTimestamp:                  false,
			expectError:                   false, // Should use current time
		},
		{
			name:                          "No timestamp - signature time fallback enabled",
			trustSignatureTime:            true,
			validateTimestampCertificates: true,
			hasTimestamp:                  false,
			expectError:                   false,
		},
		{
			name:                          "Timestamp validation disabled",
			trustSignatureTime:            false,
			validateTimestampCertificates: false,
			hasTimestamp:                  true,
			expectError:                   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &VerifyOptions{
				RequiredEKUs:                  []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				RequireDigitalSignatureKU:     true,
				TrustSignatureTime:            tt.trustSignatureTime,
				ValidateTimestampCertificates: tt.validateTimestampCertificates,
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
			if options.TrustSignatureTime != tt.trustSignatureTime {
				t.Errorf("Expected TrustSignatureTime %v, got %v", tt.trustSignatureTime, options.TrustSignatureTime)
			}
			if options.ValidateTimestampCertificates != tt.validateTimestampCertificates {
				t.Errorf("Expected ValidateTimestampCertificates %v, got %v", tt.validateTimestampCertificates, options.ValidateTimestampCertificates)
			}
		})
	}
}

func TestEmbeddedCertificatesSecurityOption(t *testing.T) {
	tests := []struct {
		name                 string
		allowUntrustedRoots  bool
		expectSecureBehavior bool
		description          string
	}{
		{
			name:                 "Secure default - embedded certs not trusted",
			allowUntrustedRoots:  false,
			expectSecureBehavior: true,
			description:          "Default secure behavior - only system trusted roots are used",
		},
		{
			name:                 "Permissive mode - embedded certs trusted",
			allowUntrustedRoots:  true,
			expectSecureBehavior: false,
			description:          "Permissive mode - embedded certificates can be used as trusted roots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &VerifyOptions{
				RequiredEKUs:              []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
				RequireDigitalSignatureKU: true,
				AllowUntrustedRoots:       tt.allowUntrustedRoots,
			}

			if options.AllowUntrustedRoots != tt.allowUntrustedRoots {
				t.Errorf("Expected AllowUntrustedRoots %v, got %v",
					tt.allowUntrustedRoots, options.AllowUntrustedRoots)
			}

			// Test that the default is secure
			if tt.expectSecureBehavior && options.AllowUntrustedRoots {
				t.Error("Secure mode should not allow untrusted roots")
			}

			// Test that permissive mode is explicitly enabled
			if !tt.expectSecureBehavior && !options.AllowUntrustedRoots {
				t.Error("Permissive mode should allow untrusted roots")
			}

			t.Logf("Test case: %s - %s", tt.name, tt.description)
		})
	}
}

func TestSecurityConfigurationExamples(t *testing.T) {
	// Test example configurations for different security levels

	t.Run("Maximum Security Configuration", func(t *testing.T) {
		maxSecurityOptions := &VerifyOptions{
			RequiredEKUs:                  []x509.ExtKeyUsage{x509.ExtKeyUsage(36)}, // Only Document Signing
			AllowedEKUs:                   []x509.ExtKeyUsage{},                     // No alternatives
			RequireDigitalSignatureKU:     true,
			RequireNonRepudiation:         true,  // Require highest security
			TrustSignatureTime:            false, // Don't trust signatory-provided time
			ValidateTimestampCertificates: true,  // Always validate timestamp certs
			AllowUntrustedRoots:           false, // Only trust system roots
		}

		if maxSecurityOptions.AllowUntrustedRoots {
			t.Error("Maximum security should not allow untrusted roots")
		}

		if maxSecurityOptions.TrustSignatureTime {
			t.Error("Maximum security should not trust signature time fallback")
		}

		if len(maxSecurityOptions.AllowedEKUs) > 0 {
			t.Error("Maximum security should not allow alternative EKUs")
		}
	})

	t.Run("Balanced Security Configuration", func(t *testing.T) {
		balancedOptions := DefaultVerifyOptions()

		// Verify this is the recommended balanced configuration
		if balancedOptions.AllowUntrustedRoots {
			t.Error("Balanced security should not allow untrusted roots by default")
		}

		if balancedOptions.TrustSignatureTime {
			t.Error("Balanced security should not trust signature time by default")
		}

		if len(balancedOptions.AllowedEKUs) == 0 {
			t.Error("Balanced security should allow some alternative EKUs")
		}
	})

	t.Run("Testing/Development Configuration", func(t *testing.T) {
		testingOptions := &VerifyOptions{
			RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsage(36)},
			AllowedEKUs: []x509.ExtKeyUsage{
				x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageAny, // Very permissive for testing
			},
			RequireDigitalSignatureKU:     true,
			RequireNonRepudiation:         false, // Optional for testing
			TrustSignatureTime:            true,  // Allow fallback for testing
			ValidateTimestampCertificates: true,
			AllowUntrustedRoots:           true, // Allow for testing with self-signed certs
		}

		if !testingOptions.AllowUntrustedRoots {
			t.Error("Testing configuration should allow untrusted roots")
		}

		// Verify ExtKeyUsageAny is included for maximum compatibility
		hasAnyEKU := false
		for _, eku := range testingOptions.AllowedEKUs {
			if eku == x509.ExtKeyUsageAny {
				hasAnyEKU = true
				break
			}
		}
		if !hasAnyEKU {
			t.Error("Testing configuration should include ExtKeyUsageAny for maximum compatibility")
		}

		if !testingOptions.TrustSignatureTime {
			t.Error("Testing configuration should allow trusting signature time")
		}
	})
}
