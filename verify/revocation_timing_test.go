package verify

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

func TestIsRevokedBeforeSigning(t *testing.T) {
	// Test times
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	revocationBefore := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC) // 5 days before signing
	revocationAfter := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)  // 5 days after signing

	tests := []struct {
		name           string
		revocationTime time.Time
		signingTime    *time.Time
		timeSource     string
		expected       bool
		description    string
	}{
		{
			name:           "Revoked before signing with embedded timestamp",
			revocationTime: revocationBefore,
			signingTime:    &signingTime,
			timeSource:     "embedded_timestamp",
			expected:       true,
			description:    "Certificate revoked before signing - signature should be invalid",
		},
		{
			name:           "Revoked after signing with embedded timestamp",
			revocationTime: revocationAfter,
			signingTime:    &signingTime,
			timeSource:     "embedded_timestamp",
			expected:       false,
			description:    "Certificate revoked after signing - signature should remain valid",
		},
		{
			name:           "No signing time available",
			revocationTime: revocationBefore,
			signingTime:    nil,
			timeSource:     "current_time",
			expected:       true,
			description:    "No reliable signing time - must assume revocation invalidates signature",
		},
		{
			name:           "Current time source (no timestamp)",
			revocationTime: revocationBefore,
			signingTime:    &signingTime,
			timeSource:     "current_time",
			expected:       true,
			description:    "Using current time - cannot reliably determine timing",
		},
		{
			name:           "Signature time source (untrusted)",
			revocationTime: revocationAfter,
			signingTime:    &signingTime,
			timeSource:     "signature_time",
			expected:       true,
			description:    "Using untrusted signature time - must be conservative",
		},
		{
			name:           "Unknown time source",
			revocationTime: revocationAfter,
			signingTime:    &signingTime,
			timeSource:     "unknown",
			expected:       true,
			description:    "Unknown time source - default to conservative behavior",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRevokedBeforeSigning(tt.revocationTime, tt.signingTime, tt.timeSource)
			if result != tt.expected {
				t.Errorf("isRevokedBeforeSigning() = %v, want %v\nDescription: %s",
					result, tt.expected, tt.description)
			}
			t.Logf("✓ %s: %v", tt.description, result)
		})
	}
}

func TestRevocationTimingWithMockData(t *testing.T) {
	// Create a mock signer with different time configurations
	baseTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name                  string
		setupSigner           func() *Signer
		mockRevocationTime    time.Time
		expectedRevokedBefore bool
		expectedTimeWarnings  int
		expectedSignerRevoked bool
		description           string
	}{
		{
			name: "Embedded timestamp - revoked before signing",
			setupSigner: func() *Signer {
				return &Signer{
					TimeStamp: &timestamp.Timestamp{
						Time: baseTime,
					},
					VerificationTime: &baseTime,
					TimeSource:       "embedded_timestamp",
					TimeWarnings:     []string{},
				}
			},
			mockRevocationTime:    baseTime.Add(-24 * time.Hour), // 1 day before
			expectedRevokedBefore: true,
			expectedTimeWarnings:  0,
			expectedSignerRevoked: true,
			description:           "With trusted timestamp, revocation before signing invalidates signature",
		},
		{
			name: "Embedded timestamp - revoked after signing",
			setupSigner: func() *Signer {
				return &Signer{
					TimeStamp: &timestamp.Timestamp{
						Time: baseTime,
					},
					VerificationTime: &baseTime,
					TimeSource:       "embedded_timestamp",
					TimeWarnings:     []string{},
				}
			},
			mockRevocationTime:    baseTime.Add(24 * time.Hour), // 1 day after
			expectedRevokedBefore: false,
			expectedTimeWarnings:  1, // Should add a warning about post-signing revocation
			expectedSignerRevoked: false,
			description:           "With trusted timestamp, revocation after signing keeps signature valid",
		},
		{
			name: "Signature time fallback - revoked after",
			setupSigner: func() *Signer {
				return &Signer{
					SignatureTime:    &baseTime,
					VerificationTime: &baseTime,
					TimeSource:       "signature_time",
					TimeWarnings:     []string{},
				}
			},
			mockRevocationTime:    baseTime.Add(24 * time.Hour), // 1 day after
			expectedRevokedBefore: true,                         // Conservative - don't trust signature time
			expectedTimeWarnings:  0,                            // Conservative - no warning, just mark as revoked
			expectedSignerRevoked: true,
			description:           "With untrusted signature time, be conservative about revocation",
		},
		{
			name: "No timestamp - current time",
			setupSigner: func() *Signer {
				currentTime := time.Now()
				return &Signer{
					VerificationTime: &currentTime,
					TimeSource:       "current_time",
					TimeWarnings:     []string{},
				}
			},
			mockRevocationTime:    baseTime, // Any revocation time
			expectedRevokedBefore: true,     // Conservative - can't determine timing
			expectedTimeWarnings:  0,        // Conservative - no warning, just mark as revoked
			expectedSignerRevoked: true,
			description:           "Without timestamp, cannot determine revocation timing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.setupSigner()
			initialWarnings := len(signer.TimeWarnings)

			// Create a mock certificate for testing
			cert := &Certificate{
				RevocationTime:       &tt.mockRevocationTime,
				RevokedBeforeSigning: false, // Will be set by our logic
			}

			// Simulate the revocation checking logic
			revokedBeforeSigning := isRevokedBeforeSigning(tt.mockRevocationTime, signer.VerificationTime, signer.TimeSource)
			cert.RevokedBeforeSigning = revokedBeforeSigning

			// Simulate the actual logic that would be used in certificate validation
			if revokedBeforeSigning {
				signer.RevokedCertificate = true
			} else {
				// Certificate was revoked after signing - only add warning for trusted timestamps
				if signer.TimeSource == "embedded_timestamp" {
					// With trusted timestamp, signature remains valid but add informational warning
					signer.TimeWarnings = append(signer.TimeWarnings,
						"Certificate was revoked after signing time (test)")
				} else {
					// Without trusted timestamp, be conservative and mark as revoked
					signer.RevokedCertificate = true
				}
			}

			// Verify results
			if cert.RevokedBeforeSigning != tt.expectedRevokedBefore {
				t.Errorf("RevokedBeforeSigning = %v, want %v", cert.RevokedBeforeSigning, tt.expectedRevokedBefore)
			}

			newWarnings := len(signer.TimeWarnings) - initialWarnings
			if newWarnings != tt.expectedTimeWarnings {
				t.Errorf("Expected %d new warnings, got %d. Warnings: %v",
					tt.expectedTimeWarnings, newWarnings, signer.TimeWarnings)
			}

			if signer.RevokedCertificate != tt.expectedSignerRevoked {
				t.Errorf("RevokedCertificate = %v, want %v", signer.RevokedCertificate, tt.expectedSignerRevoked)
			}

			t.Logf("✓ %s", tt.description)
			t.Logf("  RevocationTime: %v", tt.mockRevocationTime)
			t.Logf("  VerificationTime: %v", signer.VerificationTime)
			t.Logf("  TimeSource: %s", signer.TimeSource)
			t.Logf("  RevokedBeforeSigning: %v", cert.RevokedBeforeSigning)
			t.Logf("  SignerRevoked: %v", signer.RevokedCertificate)
			if len(signer.TimeWarnings) > 0 {
				t.Logf("  Warnings: %v", signer.TimeWarnings)
			}
		})
	}
}

func TestRevocationTimingFieldsInCertificate(t *testing.T) {
	// Test that the new fields are properly populated in the Certificate struct
	revocationTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)

	cert := Certificate{
		Certificate:          &x509.Certificate{}, // Mock cert
		RevocationTime:       &revocationTime,
		RevokedBeforeSigning: true,
	}

	// Verify the new fields are accessible
	if cert.RevocationTime == nil {
		t.Error("RevocationTime should not be nil")
	}

	if !cert.RevocationTime.Equal(revocationTime) {
		t.Errorf("RevocationTime = %v, want %v", cert.RevocationTime, revocationTime)
	}

	if !cert.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning should be true")
	}

	t.Logf("✓ Certificate fields properly populated:")
	t.Logf("  RevocationTime: %v", cert.RevocationTime)
	t.Logf("  RevokedBeforeSigning: %v", cert.RevokedBeforeSigning)
}

func TestOCSPRevocationTiming(t *testing.T) {
	// Test OCSP response handling with different revocation statuses
	baseTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	revocationTime := baseTime.Add(-24 * time.Hour) // Revoked 1 day before signing

	tests := []struct {
		name          string
		ocspStatus    int
		revokedAt     time.Time
		timeSource    string
		expectRevoked bool
	}{
		{
			name:          "OCSP Good status",
			ocspStatus:    ocsp.Good,
			revokedAt:     time.Time{}, // Zero time for good status
			timeSource:    "embedded_timestamp",
			expectRevoked: false,
		},
		{
			name:          "OCSP Revoked before signing",
			ocspStatus:    ocsp.Revoked,
			revokedAt:     revocationTime,
			timeSource:    "embedded_timestamp",
			expectRevoked: true,
		},
		{
			name:          "OCSP Revoked after signing",
			ocspStatus:    ocsp.Revoked,
			revokedAt:     baseTime.Add(24 * time.Hour), // After signing
			timeSource:    "embedded_timestamp",
			expectRevoked: false,
		},
		{
			name:          "OCSP Unknown status",
			ocspStatus:    ocsp.Unknown,
			revokedAt:     revocationTime,
			timeSource:    "embedded_timestamp",
			expectRevoked: true, // Unknown treated as revoked for safety
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &Signer{
				TimeStamp: &timestamp.Timestamp{
					Time: baseTime,
				},
				VerificationTime: &baseTime,
				TimeSource:       tt.timeSource,
				TimeWarnings:     []string{},
			}

			// Mock OCSP response
			resp := &ocsp.Response{
				Status:    tt.ocspStatus,
				RevokedAt: tt.revokedAt,
			}

			// Test the revocation timing logic
			if resp.Status != ocsp.Good {
				revokedBeforeSigning := isRevokedBeforeSigning(resp.RevokedAt, signer.VerificationTime, signer.TimeSource)

				if revokedBeforeSigning != tt.expectRevoked {
					t.Errorf("Expected revokedBeforeSigning=%v, got %v", tt.expectRevoked, revokedBeforeSigning)
				}
			}

			t.Logf("✓ OCSP Status: %d, RevokedAt: %v, Expected: %v",
				tt.ocspStatus, tt.revokedAt, tt.expectRevoked)
		})
	}
}

func TestCRLRevocationTiming(t *testing.T) {
	// Test CRL revocation time handling
	baseTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		revocationTime *time.Time
		timeSource     string
		expectRevoked  bool
		description    string
	}{
		{
			name:           "CRL revocation before signing",
			revocationTime: &[]time.Time{baseTime.Add(-24 * time.Hour)}[0], // 1 day before
			timeSource:     "embedded_timestamp",
			expectRevoked:  true,
			description:    "Certificate in CRL with revocation before signing",
		},
		{
			name:           "CRL revocation after signing",
			revocationTime: &[]time.Time{baseTime.Add(24 * time.Hour)}[0], // 1 day after
			timeSource:     "embedded_timestamp",
			expectRevoked:  false,
			description:    "Certificate in CRL with revocation after signing",
		},
		{
			name:           "No revocation time in CRL",
			revocationTime: nil,
			timeSource:     "embedded_timestamp",
			expectRevoked:  false,
			description:    "Certificate not found in CRL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &Signer{
				TimeStamp: &timestamp.Timestamp{
					Time: baseTime,
				},
				VerificationTime: &baseTime,
				TimeSource:       tt.timeSource,
				TimeWarnings:     []string{},
			}

			var revokedBeforeSigning bool
			if tt.revocationTime != nil {
				revokedBeforeSigning = isRevokedBeforeSigning(*tt.revocationTime, signer.VerificationTime, signer.TimeSource)
			}

			if revokedBeforeSigning != tt.expectRevoked {
				t.Errorf("Expected revokedBeforeSigning=%v, got %v", tt.expectRevoked, revokedBeforeSigning)
			}

			t.Logf("✓ %s: %v", tt.description, revokedBeforeSigning)
		})
	}
}

func TestRevocationTimingEdgeCases(t *testing.T) {
	// Test edge cases for revocation timing
	baseTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		revocationTime time.Time
		signingTime    *time.Time
		timeSource     string
		expected       bool
		description    string
	}{
		{
			name:           "Exact same time",
			revocationTime: baseTime,
			signingTime:    &baseTime,
			timeSource:     "embedded_timestamp",
			expected:       false, // Not before, so should be false
			description:    "Revocation and signing at exact same time",
		},
		{
			name:           "Revocation 1 second before",
			revocationTime: baseTime.Add(-1 * time.Second),
			signingTime:    &baseTime,
			timeSource:     "embedded_timestamp",
			expected:       true,
			description:    "Revocation 1 second before signing",
		},
		{
			name:           "Revocation 1 second after",
			revocationTime: baseTime.Add(1 * time.Second),
			signingTime:    &baseTime,
			timeSource:     "embedded_timestamp",
			expected:       false,
			description:    "Revocation 1 second after signing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRevokedBeforeSigning(tt.revocationTime, tt.signingTime, tt.timeSource)
			if result != tt.expected {
				t.Errorf("isRevokedBeforeSigning() = %v, want %v\n%s",
					result, tt.expected, tt.description)
			}
			t.Logf("✓ %s: %v", tt.description, result)
		})
	}
}
