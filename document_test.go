package pdfsign

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func TestSignBuilder_FluentAPI(t *testing.T) {
	doc := &Document{}
	cert := &x509.Certificate{}

	sb := doc.Sign(nil, cert)
	sb.Contact("email@example.com").
		Type(CertificationSignature).
		Permission(AllowFormFilling).
		Format(PAdES_B_LTA).
		Timestamp("http://tsa.example.com").
		TimestampAuth("user", "pass").
		Digest(crypto.SHA512).
		C2PACreator("TestApp").
		C2PAClaimGenerator("TestGen")

	if sb.contact != "email@example.com" {
		t.Errorf("Expected contact email@example.com, got %s", sb.contact)
	}
	if sb.sigType != CertificationSignature {
		t.Errorf("Expected sigType CertificationSignature, got %v", sb.sigType)
	}
	if sb.permission != AllowFormFilling {
		t.Errorf("Expected permission AllowFormFilling, got %v", sb.permission)
	}
	if sb.format != PAdES_B_LTA {
		t.Errorf("Expected format PAdES_B_LTA, got %v", sb.format)
	}
	if sb.tsa != "http://tsa.example.com" {
		t.Errorf("Expected tsa http://tsa.example.com, got %s", sb.tsa)
	}
	if sb.tsaUser != "user" {
		t.Errorf("Expected tsaUser user, got %s", sb.tsaUser)
	}
	if sb.tsaPass != "pass" {
		t.Errorf("Expected tsaPass pass, got %s", sb.tsaPass)
	}
	if sb.digest != crypto.SHA512 {
		t.Errorf("Expected digest SHA512, got %v", sb.digest)
	}
	if sb.c2paCreator != "TestApp" {
		t.Errorf("Expected c2paCreator TestApp, got %s", sb.c2paCreator)
	}
	if sb.c2paClaim != "TestGen" {
		t.Errorf("Expected c2paClaim TestGen, got %s", sb.c2paClaim)
	}
}

func TestDocument_SimpleMethods(t *testing.T) {
	doc := &Document{}

	// Timestamp builder
	ts := doc.Timestamp("http://tsa.example.com")
	if ts == nil {
		t.Error("Timestamp builder returned nil")
	}

	// Compliance
	doc.SetCompliance(PDFA_1B)

	// Reader (will be nil for empty doc, but method runs)
	if doc.Reader() != nil {
		t.Error("Expected nil reader for empty doc")
	}

	// Open invalid file
	_, err := OpenFile("non_existent_file.pdf")
	if err == nil {
		t.Error("Expected error opening non-existent file")
	}
}
