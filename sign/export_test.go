package sign

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

// ExportedLoadCertificateAndKey makes LoadCertificateAndKey available to external tests (package sign_test).
func ExportedLoadCertificateAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	return LoadCertificateAndKey(t)
}
