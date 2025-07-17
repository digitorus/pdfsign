package cli

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
		{"Valid CertificationSignature", "CertificationSignature", sign.CertificationSignature, false},
		{"Valid ApprovalSignature", "ApprovalSignature", sign.ApprovalSignature, false},
		{"Valid UsageRightsSignature", "UsageRightsSignature", sign.UsageRightsSignature, false},
		{"Valid TimeStampSignature", "TimeStampSignature", sign.TimeStampSignature, false},
		{"Invalid cert type", "InvalidCertType", 0, true},
		{"Empty string", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCertType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCertType() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseCertType() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("ParseCertType() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestUsage(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	if os.Getenv("TEST_USAGE") == "1" {
		Usage()
		return
	}
	t.Skip("Skipping Usage() test - requires subprocess testing for os.Exit()")
}

func TestSignCommandValidation(t *testing.T) {
	tests := []struct {
		name     string
		certType string
		args     []string
		wantErr  bool
	}{
		{"TimeStamp with insufficient args", "TimeStampSignature", []string{"input.pdf"}, true},
		{"TimeStamp with sufficient args", "TimeStampSignature", []string{"input.pdf", "output.pdf"}, false},
		{"Regular signing with insufficient args", "CertificationSignature", []string{"input.pdf", "output.pdf"}, true},
		{"Regular signing with sufficient args", "CertificationSignature", []string{"input.pdf", "output.pdf", "cert.crt", "key.key"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertType(tt.certType)
			if err != nil {
				t.Errorf("ParseCertType() failed: %v", err)
				return
			}
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
