//go:build certificateExpired
// +build certificateExpired

// TODO: Rework tests, these currently fail because of expired certificate
package sign

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/digitorus/pdfsign/revocation"
)

const certPem = `-----BEGIN CERTIFICATE-----
MIIGKDCCBRCgAwIBAgIMW8J4m7huCPO5f+wbMA0GCSqGSIb3DQEBCwUAMEsxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSEwHwYDVQQDExhH
bG9iYWxTaWduIENBIDIgZm9yIEFBVEwwHhcNMTcwNzA2MDk0MDUyWhcNMjAwNzA2
MDk0MDUyWjCBpzELMAkGA1UEBhMCR0IxDTALBgNVBAgTBEtlbnQxEjAQBgNVBAcT
CU1haWRzdG9uZTEfMB0GA1UEChMWR01PIEdsb2JhbFNpZ24gTGltaXRlZDEfMB0G
A1UEAxMWUGF1bCBWYW4gQnJvdXdlcnNoYXZlbjEzMDEGCSqGSIb3DQEJARYkcGF1
bC52YW5icm91d2Vyc2hhdmVuQGdsb2JhbHNpZ24uY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAr5jbAIZDjkWngxlwJqneE9VEDTvmMIGwvgy71g5j
k+igHxB6tTfaqGD87oIm2wcrlZHpPJG9n2Rh9FhFmvx8ZXiceNI9Ks5Ho5iYNFUk
y2JuVfFPxtp6amqpLzM5HZUePgu1Gdy1Zn1PUajii7paFPuhdemcA9DdTAQ1GsDv
C9MZ2D5sKM0hLCRePCzJ3TeQmHefFrC0XQ7u2i7LDD990URiFz7WNq2tSDJwBe/6
1tMewpekmtE5X43PqzgcyGBsDJqAKcthsLQnhqrIryuwE2bEhP/FxQrHkT+f/OkK
vwAjB9gYgJRNoMFUwXLW789JsOkbCqepoWsg1PnWrAbAMQIDAQABo4ICrTCCAqkw
DgYDVR0PAQH/BAQDAgeAMIGIBggrBgEFBQcBAQR8MHowQQYIKwYBBQUHMAKGNWh0
dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzYWF0bDJzaGEyZzIu
Y3J0MDUGCCsGAQUFBzABhilodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vZ3Nh
YXRsMnNoYTJnMjCB2wYDVR0gBIHTMIHQMIHNBgsrBgEEAaAyASgeAjCBvTCBhgYI
KwYBBQUHAgIwegx4VGhpcyBjZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQgaW4g
YWNjb3JkYW5jZSB3aXRoIHRoZSBHbG9iYWxTaWduIENQUyBsb2NhdGVkIGF0IGh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDIGCCsGAQUFBwIB
FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAJBgNVHRME
AjAAMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Z3MvZ3NhYXRsMnNoYTJnMi5jcmwwLwYDVR0RBCgwJoEkcGF1bC52YW5icm91d2Vy
c2hhdmVuQGdsb2JhbHNpZ24uY29tMFwGCiqGSIb3LwEBCQEETjBMAgEBhkRodHRw
Oi8vYWF0bC10aW1lc3RhbXAuZ2xvYmFsc2lnbi5jb20vdHNhL2FvaGZld2F0MjM4
OTUzNWZuYXNnbmxnNW0yMwEBADATBgNVHSUEDDAKBggrBgEFBQcDBDAdBgNVHQ4E
FgQUtimjVds00OgBZ747tqkKbZJeCCowHwYDVR0jBBgwFoAUxRNOzofGiRsj6EDj
dTKbA3A67+8wDQYJKoZIhvcNAQELBQADggEBACBUFVwUKVpOWt1eLf7lKKPfVhEL
9QrkAkV/UZPMsDwBDIJhphqjCqfbJVTgybm79gUCJiwbarCYOHRgFAdNTPEvEcT0
+XwR6WZcDdfQAtaHfO6X9ExgJv93txoFVcpYLY1hR3o6QdP4VQSDhRTv3bM1j/WC
mcCoiIQz28Y8L+8rRx5J7JAgYpupoU/8sCpidBMhYAGF5p8Z8p0LbqvZndRHaVqp
yXQ0kYj1n45it5FXsKECWZKTx0v4IBySJY3RGpF+5cpPUYulJfINBg7nj7aQG/Uv
qtyxnVAG3W4pTHWd/0Gyc3lrgRtyZy+b9DaxHZ/N6HHNgnRHB4PUkektpX4=
-----END CERTIFICATE-----`

const issuerPem = `-----BEGIN CERTIFICATE-----
MIIEpjCCA46gAwIBAgIORea3r9ymcb22XRTz2sAwDQYJKoZIhvcNAQELBQAwVzEL
MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLTArBgNVBAMT
JEdsb2JhbFNpZ24gQ0EgZm9yIEFBVEwgLSBTSEEyNTYgLSBHMjAeFw0xNDEyMTAw
MDAwMDBaFw0yNDEyMTAwMDAwMDBaMEsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
bG9iYWxTaWduIG52LXNhMSEwHwYDVQQDExhHbG9iYWxTaWduIENBIDIgZm9yIEFB
VEwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJS4vhNfaSmXtX7bWy
hVhBGqisbqgnX9/K5psHMrkwm10pnicCSmvb6nvgMAPbRPyfpGHj5ArrDli6rCDR
CLR1tjied/6AxQCCPgyvDyEwDWxzytVHkCldzEHjHmc1kL0zI7aQfNrD25xAUnHa
X2jBm71filgduyQBfuLJLlL/NGh46X6eI9xpqBmqwBFa6wHPisnwkAB22CQB/OY3
mnlhLCJmrEL9fGPRDQnc6w849ws3nkKISkEPmTyfUAJUkEgCxOjfiwoNSFjZ99lA
K+ujj90dqYU3mJ7dTEHA2+dFrdvVsoyA4JZBu7utxe2rJgpifO3B/L+f4Cat12kA
2IqtAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUxRNOzofGiRsj6EDjdTKbA3A67+8wHwYDVR0jBBgwFoAU
YMLxUj6tjBPc28oO+grmKiyZS9gwgYYGCCsGAQUFBwEBBHoweDA0BggrBgEFBQcw
AYYoaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzYWF0bHNoYTJnMjBABggr
BgEFBQcwAoY0aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nh
YXRsc2hhMmcyLmNydDA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vY3JsLmdsb2Jh
bHNpZ24uY29tL2dzL2dzYWF0bHNoYTJnMi5jcmwwRwYDVR0gBEAwPjA8BgRVHSAA
MDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9z
aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAkH9vI0bJPzbtf5ikdFb5Kc4L9/IIZ
GPeVbS3UPl8x4WPzmZHwGvSeG53DDcJ9weGHO4PORBgBT5KDZEt7CKXd4vt83xw8
P1kYvvjv4E+8R8VD3hP48zkygHMR3JtBdMPkbNbE10TCb4XmQPpkwGIVhaD7ojtS
+4mPjVts6ZZzbnHI42CbYwdaOf2W8IUu0b1w4T7T5YPfi8rSKwQxIKibFG1mSsOC
vG9tDxJVJUNdiWTPoHGn+n+3qeJvPRgHhicZ+ivOqqmLQSNgtp1WdQ+uJmUqU7EY
htN+laG7bS/8xGTPothL9Abgd/9L3X0KKGUDCdcpzRuy20CI7E4uygD8
-----END CERTIFICATE-----`

func TestEmbedRevocationStatus(t *testing.T) {
	var ia revocation.InfoArchival

	err := DefaultEmbedRevocationStatusFunction(pemToCert(certPem), pemToCert(issuerPem), &ia)
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	if len(ia.OCSP) != 1 {
		t.Errorf("Expected one OCSP status")
	}
}

func TestEmbedOCSPRevocationStatus(t *testing.T) {
	var ia revocation.InfoArchival

	err := embedOCSPRevocationStatus(pemToCert(certPem), pemToCert(issuerPem), &ia)
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	if len(ia.OCSP) != 1 {
		t.Errorf("Expected one OCSP status")
	}
}

func TestEmbedCRLRevocationStatus(t *testing.T) {
	var ia revocation.InfoArchival

	err := embedCRLRevocationStatus(pemToCert(certPem), nil, &ia)
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	if len(ia.CRL) != 1 {
		t.Errorf("Expected one CRL")
	}
}

func pemToCert(p string) *x509.Certificate {
	block, _ := pem.Decode([]byte(p))
	cert, _ := x509.ParseCertificate(block.Bytes)

	return cert
}
