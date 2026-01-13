package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestSignatureSize(t *testing.T) {
	tests := []struct {
		name     string
		keyBits  int
		keyType  string
		wantSize int
	}{
		{"RSA-1024", 1024, "RSA", 128},
		{"RSA-2048", 2048, "RSA", 256},
		{"RSA-3072", 3072, "RSA", 384},
		{"RSA-4096", 4096, "RSA", 512},
		{"ECDSA-P256", 256, "ECDSA", 73},  // 2*32 + 9 = 73 (DER overhead)
		{"ECDSA-P384", 384, "ECDSA", 105}, // 2*48 + 9 = 105
		{"ECDSA-P521", 521, "ECDSA", 141}, // 2*66 + 9 = 141
		{"Ed25519", 0, "Ed25519", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var signer crypto.Signer
			var err error

			switch tt.keyType {
			case "RSA":
				signer, err = rsa.GenerateKey(rand.Reader, tt.keyBits)
			case "ECDSA":
				var curve elliptic.Curve
				switch tt.keyBits {
				case 256:
					curve = elliptic.P256()
				case 384:
					curve = elliptic.P384()
				case 521:
					curve = elliptic.P521()
				}
				signer, err = ecdsa.GenerateKey(curve, rand.Reader)
			case "Ed25519":
				_, signer, err = ed25519.GenerateKey(rand.Reader)
			}

			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			gotSize, err := SignatureSize(signer)
			if err != nil {
				t.Fatalf("SignatureSize failed: %v", err)
			}

			if gotSize != tt.wantSize {
				t.Errorf("SignatureSize() = %d, want %d", gotSize, tt.wantSize)
			}
		})
	}
}

func TestSignatureSize_Errors(t *testing.T) {
	t.Run("nil signer", func(t *testing.T) {
		_, err := SignatureSize(nil)
		if !errors.Is(err, ErrNilSigner) {
			t.Errorf("expected ErrNilSigner, got %v", err)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := PublicKeySignatureSize(struct{}{})
		if !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("expected ErrUnsupportedKey, got %v", err)
		}
	})

	t.Run("nil public key", func(t *testing.T) {
		_, err := PublicKeySignatureSize(nil)
		if !errors.Is(err, ErrNilPublicKey) {
			t.Errorf("expected ErrNilPublicKey, got %v", err)
		}
	})
}

func TestPublicKeySignatureSize_RSA(t *testing.T) {
	// Test that RSA public key size calculation matches key.Size()
	for _, bits := range []int{1024, 2048, 3072, 4096} {
		t.Run("RSA-"+string(rune('0'+bits/1000))+string(rune('0'+(bits%1000)/100))+string(rune('0'+(bits%100)/10))+string(rune('0'+bits%10)), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			size, err := PublicKeySignatureSize(&key.PublicKey)
			if err != nil {
				t.Fatalf("PublicKeySignatureSize failed: %v", err)
			}

			if size != key.Size() {
				t.Errorf("PublicKeySignatureSize() = %d, want %d (key.Size())", size, key.Size())
			}

			if size != bits/8 {
				t.Errorf("PublicKeySignatureSize() = %d, want %d (bits/8)", size, bits/8)
			}
		})
	}
}

func createTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestValidateSignerCertificateMatch(t *testing.T) {
	// Generate matching pair
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	cert1 := createTestCertificate(t, key1)

	// Generate mismatched pair
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	t.Run("matching keys", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(key1, cert1)
		if err != nil {
			t.Errorf("expected no error for matching keys, got %v", err)
		}
	})

	t.Run("mismatched keys", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(key2, cert1)
		if !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("expected ErrKeyMismatch, got %v", err)
		}
	})

	t.Run("nil signer", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(nil, cert1)
		if !errors.Is(err, ErrNilSigner) {
			t.Errorf("expected ErrNilSigner, got %v", err)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(key1, nil)
		if !errors.Is(err, ErrNilCertificate) {
			t.Errorf("expected ErrNilCertificate, got %v", err)
		}
	})
}

func TestValidateSignerCertificateMatch_DifferentKeyTypes(t *testing.T) {
	// Generate ECDSA key and certificate
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	ecCert := createTestCertificate(t, ecKey)

	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	t.Run("RSA signer with EC certificate", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(rsaKey, ecCert)
		if !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("expected ErrKeyMismatch for mismatched key types, got %v", err)
		}
	})

	t.Run("EC signer with EC certificate", func(t *testing.T) {
		err := ValidateSignerCertificateMatch(ecKey, ecCert)
		if err != nil {
			t.Errorf("expected no error for matching EC keys, got %v", err)
		}
	})
}

// BenchmarkSignatureSize benchmarks the signature size calculation
func BenchmarkSignatureSize(b *testing.B) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	b.Run("RSA-4096", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = SignatureSize(rsaKey)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = SignatureSize(ecKey)
		}
	})

	b.Run("Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = SignatureSize(edKey)
		}
	})
}

// BenchmarkValidateSignerCertificateMatch benchmarks the validation function
func BenchmarkValidateSignerCertificateMatch(b *testing.B) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a certificate manually for benchmarking
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, rsaKey.Public(), rsaKey)
	cert, _ := x509.ParseCertificate(certDER)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSignerCertificateMatch(rsaKey, cert)
	}
}
