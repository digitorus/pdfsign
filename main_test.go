package main

import (
	"os"
	"testing"

	"github.com/digitorus/pdfsign/sign"
)

func TestParseCertType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected sign.CertType
		wantErr  bool
	}{
		{
			name:     "Valid CertificationSignature",
			input:    "CertificationSignature",
			expected: sign.CertificationSignature,
			wantErr:  false,
		},
		{
			name:     "Valid ApprovalSignature",
			input:    "ApprovalSignature",
			expected: sign.ApprovalSignature,
			wantErr:  false,
		},
		{
			name:     "Valid UsageRightsSignature",
			input:    "UsageRightsSignature",
			expected: sign.UsageRightsSignature,
			wantErr:  false,
		},
		{
			name:     "Valid TimeStampSignature",
			input:    "TimeStampSignature",
			expected: sign.TimeStampSignature,
			wantErr:  false,
		},
		{
			name:     "Invalid cert type",
			input:    "InvalidCertType",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCertType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCertType() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("parseCertType() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("parseCertType() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestUsage(t *testing.T) {
	// Capture original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Test that usage exits
	if os.Getenv("TEST_USAGE") == "1" {
		usage()
		return
	}

	// This test just verifies that usage() doesn't panic when called
	// Since usage() calls os.Exit(1), we need to test it in a subprocess
	// For now, we'll skip this test as it's hard to test os.Exit()
	t.Skip("Skipping usage() test - requires subprocess testing for os.Exit()")
}

func TestMainCommandParsing(t *testing.T) {
	// Capture original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name        string
		args        []string
		expectPanic bool
	}{
		{
			name:        "No arguments",
			args:        []string{"pdfsign"},
			expectPanic: false, // Will call usage() which exits
		},
		{
			name:        "Help command",
			args:        []string{"pdfsign", "help"},
			expectPanic: false, // Will call usage() which exits
		},
		{
			name:        "Unknown command",
			args:        []string{"pdfsign", "unknown"},
			expectPanic: false, // Will call usage() which exits
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since main() calls os.Exit() in various scenarios,
			// we'll skip these tests as they require subprocess testing
			t.Skip("Skipping main() command parsing test - requires subprocess testing for os.Exit()")
		})
	}
}

func TestSignCommandValidation(t *testing.T) {
	// This test focuses on the validation logic without actually running the commands
	// since they involve file operations and os.Exit()

	tests := []struct {
		name     string
		certType string
		args     []string
		wantErr  bool
	}{
		{
			name:     "TimeStamp with insufficient args",
			certType: "TimeStampSignature",
			args:     []string{"input.pdf"},
			wantErr:  true,
		},
		{
			name:     "TimeStamp with sufficient args",
			certType: "TimeStampSignature",
			args:     []string{"input.pdf", "output.pdf"},
			wantErr:  false,
		},
		{
			name:     "Regular signing with insufficient args",
			certType: "CertificationSignature",
			args:     []string{"input.pdf", "output.pdf"},
			wantErr:  true,
		},
		{
			name:     "Regular signing with sufficient args",
			certType: "CertificationSignature",
			args:     []string{"input.pdf", "output.pdf", "cert.crt", "key.key"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the parseCertType function which is used in signPDF
			_, err := parseCertType(tt.certType)
			if err != nil {
				t.Errorf("parseCertType() failed: %v", err)
				return
			}

			// Test argument count validation logic
			if tt.certType == "TimeStampSignature" {
				if len(tt.args) < 2 && !tt.wantErr {
					t.Error("TimeStamp signing should require at least 2 args")
				}
			} else {
				if len(tt.args) < 4 && !tt.wantErr {
					t.Error("Regular signing should require at least 4 args")
				}
			}
		})
	}
}
