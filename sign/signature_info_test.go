// Test to demonstrate the new signature information output
package sign

import (
	"crypto"
	"os"
	"testing"
	"time"
)

func TestSignatureInfoOutput(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)

	tmpfile, err := os.CreateTemp("", "signature_info_test_")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer os.Remove(tmpfile.Name())

	result, err := SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Amsterdam, Netherlands",
				Reason:      "Testing signature info functionality",
				ContactInfo: "john.doe@example.com",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:          pkey,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     cert,
	})

	if err != nil {
		t.Fatalf("Signing failed: %s", err.Error())
	}

	if result == nil {
		t.Fatal("Expected SigningResult but got nil")
	} // Verify the result has valid hash values
	if result.DocumentHash == "" {
		t.Error("Expected DocumentHash to be populated")
	}
	if result.SignatureHash == "" {
		t.Error("Expected SignatureHash to be populated")
	}
	if result.CertificateHash == "" {
		t.Error("Expected CertificateHash to be populated")
	}

	// Assert specific certificate details match expected values from test certificate
	expectedCommonName := "Paul van Brouwershaven"
	expectedCountry := []string{"NL"}
	expectedOrganization := []string{"Digitorus"}
	expectedSerialNumber := "102283634302971898510260113702695082477055643485"
	expectedPublicKeyAlgorithm := "RSA"
	expectedSignatureAlgorithm := "SHA256-RSA"
	// Expected certificate hash (SHA256 of the test certificate)
	expectedCertificateHash := "1b4e1b530438893595f5889c9848fa6776679a8a65d0c94af493ec529dcbb7e6"

	// Verify Subject details
	if result.Certificate.Subject.CommonName != expectedCommonName {
		t.Errorf("Expected CommonName '%s', got '%s'", expectedCommonName, result.Certificate.Subject.CommonName)
	}
	if len(result.Certificate.Subject.Country) != 1 || result.Certificate.Subject.Country[0] != expectedCountry[0] {
		t.Errorf("Expected Country %v, got %v", expectedCountry, result.Certificate.Subject.Country)
	}
	if len(result.Certificate.Subject.Organization) != 1 || result.Certificate.Subject.Organization[0] != expectedOrganization[0] {
		t.Errorf("Expected Organization %v, got %v", expectedOrganization, result.Certificate.Subject.Organization)
	}
	if result.Certificate.SerialNumber.String() != expectedSerialNumber {
		t.Errorf("Expected SerialNumber '%s', got '%s'", expectedSerialNumber, result.Certificate.SerialNumber.String())
	}
	if result.Certificate.PublicKeyAlgorithm.String() != expectedPublicKeyAlgorithm {
		t.Errorf("Expected PublicKeyAlgorithm '%s', got '%s'", expectedPublicKeyAlgorithm, result.Certificate.PublicKeyAlgorithm.String())
	}
	if result.Certificate.SignatureAlgorithm.String() != expectedSignatureAlgorithm {
		t.Errorf("Expected SignatureAlgorithm '%s', got '%s'", expectedSignatureAlgorithm, result.Certificate.SignatureAlgorithm.String())
	}
	if result.CertificateHash != expectedCertificateHash {
		t.Errorf("Expected CertificateHash '%s', got '%s'", expectedCertificateHash, result.CertificateHash)
	}

	// Verify Issuer details (self-signed certificate, so issuer == subject)
	if result.Certificate.Issuer.CommonName != expectedCommonName {
		t.Errorf("Expected Issuer CommonName '%s', got '%s'", expectedCommonName, result.Certificate.Issuer.CommonName)
	}
	if len(result.Certificate.Issuer.Country) != 1 || result.Certificate.Issuer.Country[0] != expectedCountry[0] {
		t.Errorf("Expected Issuer Country %v, got %v", expectedCountry, result.Certificate.Issuer.Country)
	}
	if len(result.Certificate.Issuer.Organization) != 1 || result.Certificate.Issuer.Organization[0] != expectedOrganization[0] {
		t.Errorf("Expected Issuer Organization %v, got %v", expectedOrganization, result.Certificate.Issuer.Organization)
	}

	// Verify date validity (certificate should be valid for 100 years)
	if result.Certificate.NotBefore.After(time.Now()) {
		t.Error("Certificate should be valid (NotBefore is in the future)")
	}
	if result.Certificate.NotAfter.Before(time.Now()) {
		t.Error("Certificate should be valid (NotAfter is in the past)")
	}

	t.Logf("Document Hash (SHA256): %s", result.DocumentHash)
	t.Logf("Signature Hash (SHA256): %s", result.SignatureHash)
	t.Logf("Certificate Hash (SHA256): %s", result.CertificateHash)
	t.Logf("All certificate details verified successfully!")

	// Verify the signed file is valid
	verifySignedFile(t, tmpfile, "signature_info_test.pdf")
}
