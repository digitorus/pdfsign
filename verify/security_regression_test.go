package verify

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/timestamp"
)

func TestUntrustedTimestampTimeFallback(t *testing.T) {
	stampTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	atTime := stampTime.Add(24 * time.Hour)
	for _, tc := range []struct {
		name      string
		configure func(*VerifyOptions)
		want      *time.Time
		source    string
	}{
		{"current time", func(*VerifyOptions) {}, nil, "current_time"},
		{"caller time", func(o *VerifyOptions) { o.AtTime = atTime }, &atTime, "current_time"},
		{"explicit signature time", func(o *VerifyOptions) { o.TrustSignatureTime = true }, &atTime, "signature_time"},
		{"disabled TSA validation", func(o *VerifyOptions) { o.ValidateTimestampCertificates = false; o.AtTime = atTime }, &atTime, "current_time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := NewSigner()
			signer.TimeStamp = &timestamp.Timestamp{Time: stampTime, RawToken: []byte{0x30, 0x00}}
			signer.SignatureTime = &atTime
			signer.TimestampTrusted = true // A prior result must not survive re-resolution.
			options := DefaultVerifyOptions()
			tc.configure(options)
			before := time.Now()
			got := resolveVerificationTime(signer, options)
			if tc.want == nil {
				if got != nil || signer.VerificationTime.Before(before) || signer.VerificationTime.After(time.Now()) {
					t.Fatalf("expected current time, got %v / %v", got, signer.VerificationTime)
				}
			} else if got == nil || !got.Equal(*tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			if signer.TimestampTrusted || signer.TimeSource != tc.source || signer.TimestampStatus != "untrusted" || len(signer.Warnings) == 0 {
				t.Fatalf("untrusted time was accepted or warning missing: %+v", signer)
			}
			if !signer.IsRevokedBeforeSigning(atTime.Add(time.Hour)) {
				t.Fatal("untrusted time suppressed revocation")
			}
		})
	}
}

func TestRevocationRequiresTrustedTimestampState(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	signer := NewSigner()
	signer.TimeSource = "embedded_timestamp"
	signer.VerificationTime = &at
	cert := &Certificate{}
	if err := applyRevocationImpact(signer, cert, at.Add(time.Minute)); err == nil || !signer.RevokedCertificate {
		t.Fatal("manually populated embedded time bypassed timestamp trust")
	}
}

type unreadableRangeSource struct{ reads int }

func (s *unreadableRangeSource) ReadAt([]byte, int64) (int, error) {
	s.reads++
	return 0, fmt.Errorf("unexpected read")
}

func TestReadByteRangeChecksBeforeReading(t *testing.T) {
	for _, ranges := range []string{"[0 10 0 -20]", "[-1 1 0 1]", "[0 9223372036854775807 0 1]", "[0 1 9223372036854775807 1]", "[0 10 0 10]", "[0 1.5 2 1]", "[0 true 2 1]", "[0 1 2]", "[0 1]", "[]", "null", "(not an array)"} {
		t.Run(ranges, func(t *testing.T) {
			data := buildFormPDF(t, "<< /FT /Sig /V 5 0 R >>", "<< /Type /Sig /ByteRange "+ranges+" /Contents <01> >>")
			rdr, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			v := rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
			source := &unreadableRangeSource{}
			if _, err := readByteRange(v, source, int64(len(data))); err == nil || source.reads != 0 {
				t.Fatalf("invalid range must fail before reading: error=%v, reads=%d", err, source.reads)
			}
		})
	}
	for _, ranges := range []string{"[0 4 4 4]", "[0 2 2 2 4 4]"} {
		t.Run("valid "+ranges, func(t *testing.T) {
			data := buildFormPDF(t, "<< /FT /Sig /V 5 0 R >>", "<< /Type /Sig /ByteRange "+ranges+" /Contents <01> >>")
			rdr, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			v := rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
			got, err := readByteRange(v, bytes.NewReader(data), int64(len(data)))
			if err != nil || !bytes.Equal(got, data[:8]) {
				t.Fatalf("valid ranges: %q, %v", got, err)
			}
		})
	}
}
