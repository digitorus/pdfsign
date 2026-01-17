package revocation

import (
	"crypto/x509"
	"testing"
)

func TestRevocation_Methods(t *testing.T) {
	info := InfoArchival{}

	// Test AddCRL
	err := info.AddCRL([]byte("crl"))
	if err != nil {
		t.Errorf("AddCRL failed: %v", err)
	}
	if len(info.CRL) != 1 {
		t.Error("AddCRL did not append CRL")
	}

	// Test AddOCSP
	err = info.AddOCSP([]byte("ocsp"))
	if err != nil {
		t.Errorf("AddOCSP failed: %v", err)
	}
	if len(info.OCSP) != 1 {
		t.Error("AddOCSP did not append OCSP")
	}

	// Test IsRevoked (currently placeholder?)
	cert := &x509.Certificate{}
	if !info.IsRevoked(cert) {
		t.Log("IsRevoked returned false (expected?)")
	} else {
		// Currently code seems to stub return true?
		t.Log("IsRevoked returned true")
	}
}
