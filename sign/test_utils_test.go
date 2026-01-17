package sign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const signCertPem = `-----BEGIN CERTIFICATE-----
MIICjDCCAfWgAwIBAgIUEeqOicMEtCutCNuBNq9GAQNYD10wDQYJKoZIhvcNAQEL
BQAwVzELMAkGA1UEBhMCTkwxEzARBgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAoM
CURpZ2l0b3J1czEfMB0GA1UEAwwWUGF1bCB2YW4gQnJvdXdlcnNoYXZlbjAgFw0y
NDExMTMwOTUxMTFaGA8yMTI0MTAyMDA5NTExMVowVzELMAkGA1UEBhMCTkwxEzAR
BgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAoMCURpZ2l0b3J1czEfMB0GA1UEAwwW
UGF1bCB2YW4gQnJvdXdlcnNoYXZlbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAmrvrZiUZZ/nSmFKMsQXg5slYTQjj7nuenczt7KGPVuGA8nNOqiGktf+yep5h
2r87jPvVjVXjJVjOTKx9HMhaFECHKHKV72iQhlw4fXa8iB1EDeGuwP+pTpRWlzur
Q/YMxvemNJVcGMfTE42X5Bgqh6DvkddRTAeeqQDBD6+5VPsCAwEAAaNTMFEwHQYD
VR0OBBYEFETizi2bTLRMIknQXWDRnQ59xI99MB8GA1UdIwQYMBaAFETizi2bTLRM
IknQXWDRnQ59xI99MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEA
OBng+EzD2xA6eF/W5Wh+PthE1MpJ1QvejZBDyCOiplWFUImJAX39ZfTo/Ydfz2xR
4Jw4hOF0kSLxDK4WGtCs7mRB0d24YDJwpJj0KN5+uh3iWk5orY75FSensfLZN7YI
VuUN7Q+2v87FjWsl0w3CPcpjB6EgI5QHsNm13bkQLbQ=
-----END CERTIFICATE-----`

const signKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCau+tmJRln+dKYUoyxBeDmyVhNCOPue56dzO3soY9W4YDyc06q
IaS1/7J6nmHavzuM+9WNVeMlWM5MrH0cyFoUQIcocpXvaJCGXDh9dryIHUQN4a7A
/6lOlFaXO6tD9gzG96Y0lVwYx9MTjZfkGCqHoO+R11FMB56pAMEPr7lU+wIDAQAB
AoGADPlKsILV0YEB5mGtiD488DzbmYHwUpOs5gBDxr55HUjFHg8K/nrZq6Tn2x4i
iEvWe2i2LCaSaBQ9H/KqftpRqxWld2/uLbdml7kbPh0+57/jsuZZs3jlN76HPMTr
uYcfG2UiU/wVTcWjQLURDotdI6HLH2Y9MeJhybctywDKWaECQQDNejmEUybbg0qW
2KT5u9OykUpRSlV3yoGlEuL2VXl1w5dUMa3rw0yE4f7ouWCthWoiCn7dcPIaZeFf
5CoshsKrAkEAwMenQppKsLk62m8F4365mPxV/Lo+ODg4JR7uuy3kFcGvRyGML/FS
TB5NI+DoTmGEOZVmZeLEoeeSnO0B52Q28QJAXFJcYW4S+XImI1y301VnKsZJA/lI
KYidc5Pm0hNZfWYiKjwgDtwzF0mLhPk1zQEyzJS2p7xFq0K3XqRfpp3t/QJACW77
sVephgJabev25s4BuQnID2jxuICPxsk/t2skeSgUMq/ik0oE0/K7paDQ3V0KQmMc
MqopIx8Y3pL+f9s4kQJADWxxuF+Rb7FliXL761oa2rZHo4eciey2rPhJIU/9jpCc
xLqE5nXC5oIUTbuSK+b/poFFrtjKUFgxf0a/W2Ktsw==
-----END RSA PRIVATE KEY-----`

// LoadCertificateAndKey loads a test certificate and private key.
func LoadCertificateAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		t.Fatalf("failed to parse PEM block containing the certificate")
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		t.Fatalf("%s", err.Error())
		return nil, nil
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		t.Fatalf("failed to parse PEM block containing the private key")
		return nil, nil
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		t.Fatalf("%s", err.Error())
		return nil, nil
	}

	return cert, pkey
}
