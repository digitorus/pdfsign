package sign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// This fixture carries a Digital Signature KeyUsage bit and an Email
// Protection ExtKeyUsage (an AllowedEKUs fallback per RFC 9336) so it
// satisfies the verify package's default certificate policy - a real PDF
// signing certificate always carries these; a fixture without them isn't
// representative of what's actually being signed with in production.
const signCertPem = `-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIBATANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJOTDET
MBEGA1UECBMKU29tZS1TdGF0ZTESMBAGA1UEChMJRGlnaXRvcnVzMR8wHQYDVQQD
ExZQYXVsIHZhbiBCcm91d2Vyc2hhdmVuMCAXDTI2MDgwNjA0NTM0MVoYDzIwNzYw
ODA2MDU1MzQxWjBXMQswCQYDVQQGEwJOTDETMBEGA1UECBMKU29tZS1TdGF0ZTES
MBAGA1UEChMJRGlnaXRvcnVzMR8wHQYDVQQDExZQYXVsIHZhbiBCcm91d2Vyc2hh
dmVuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtts9/8dyImzSW0Fv
ixW++vXx4GYOysyv+w86yseu3n59+pndbpXWMaTJlVaIph3W4wCDQBWTI52BrzSy
m2KUroAqt+4AqJwjmZ/zFKMu+pteR0/S+gDwvlBfTjBju4qRL40Ib9pU85P6/2Ga
sQGYly0brFO3pR57va17Jpr3Mmomn6UIg9U5XopfPVaCbKUaWNX19ysiekCJcw1V
JV/LEid1QI+Bp5iUFTKOFee55/+37Ek7+aGQOoXq4zOrFtw0dsywGQ8+pYQmcL2H
QCFnQOauT9E+49Id7JiDz6bB5oLrW14wzD96x7h491rtiEeuw/GS1xjzxgyBYfve
ols8DwIDAQABozUwMzAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUH
AwQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEARg/gTGnTA2L+xVx9
ORwjAdrj78RMnUHX8iginqOjKOd9hVJD5c7Aa12/ajFKo/V4Yn+Zg9yUCiHgxGWW
Uj/6t/ZG9VV36WhUiBnvK/PATalSgLFifTOTOOxtkhYcEnnO5NgstheCiRv2f3be
2VeBOIM3RvZJwLuCppcdJT81ioak/L89CHho/NPRTBRGIDxqGXMxhh4GeaYPbmA5
ZFyEUG2TXiEC96J4byu81Qw7AVZhB5DdL4EU9rKb51rXMJebJxdLXRaNpaAo3lSe
T2kg0KwxL7sZeIkb0OcZxd+A4XhjY07sLBi3CkMo22D4pe2e/50rCmM4m5MMAxV7
PNmQ+A==
-----END CERTIFICATE-----`

const signKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtts9/8dyImzSW0FvixW++vXx4GYOysyv+w86yseu3n59+pnd
bpXWMaTJlVaIph3W4wCDQBWTI52BrzSym2KUroAqt+4AqJwjmZ/zFKMu+pteR0/S
+gDwvlBfTjBju4qRL40Ib9pU85P6/2GasQGYly0brFO3pR57va17Jpr3Mmomn6UI
g9U5XopfPVaCbKUaWNX19ysiekCJcw1VJV/LEid1QI+Bp5iUFTKOFee55/+37Ek7
+aGQOoXq4zOrFtw0dsywGQ8+pYQmcL2HQCFnQOauT9E+49Id7JiDz6bB5oLrW14w
zD96x7h491rtiEeuw/GS1xjzxgyBYfveols8DwIDAQABAoIBABAhNM3cNQguWzvr
gMBfEbKngUePGRzwg1F9HW2Hwbgkpk41xl+b3gIRDCsdL/6fQTZS9EDx5kHNAgSH
fH3Sa1UdPydsWiiFZWqGvnWCk4FNtTpLI0wkSxgulMmb4SBI79em9CiRtM6rrgda
/78/actkEj3YQKnTD41CwUs9fjK3HgHGR6xPpr/PXUEN+dHNGScJlb8PDmBUIQ/S
R80JVDF8/gTpiNVZG5d/NVOE/IhKx9OkDNud54YbFQYu7v/m8ucdG5uy94poTX52
vEvrKc+E6TANqIXbets3Jou1x1R5MuE/OsT4whZOIXj50PhnfEiDq3T7m+/BTLTR
1u8sudECgYEAwtfTWDB2YBpTpOO0t1tzNoIYmMfOWDy8X4WOdm12/Z5qtCu3Lky5
eZ4eDP9xY38egtLvLx683+eBAFGejmJraq4rbbjStiFU3aFFA84hUV6ANh0MFhkH
NkqmZHDVZ++qgDVP0cEpfVQC/R1RRgE7RQiLZUtHYjN01HvgtGktZZkCgYEA8EBB
knPndYVOBJga6a01H+zCjgAqYG5h3xd18QmbE2IPaHmyeZOObCP4QnB5yhCFcqI8
Zx5YyuTFoVAW/G4Ia/1TgrpIWKE9xPItr5EFuK7HVFSnSX6U2RO1YHj5g6rrwSu4
MiGlmOHrbind/maoTZFrwkOLvOjYZY28w7UkZ+cCgYEAlvVQsYsaq+q50474fPdF
lH3HQNfNb1/fMsLvVaIKBwWt9lnIWv7m1OtErR1cZJIguYtj9UYDYBalQ/H4vqhS
QR0gWKpR1vqMHgrMxd32wmxNOZ/XtWc+xzmfIUKqlRSDLUIgzYqy8n8csa79QRfD
LAEqvxhL/jGP2vD/b8ftfEECgYEAi+1Aw6WR11aum+pjMlpZKKDip4XdKJDhm+e0
H5DyqxVf1/+ZPUn9l2pTu456wH9i2eM3vu9j07fuiwd0e80yRoMi0m7gmA5BRaWv
iiOy61+QZMNxM1LwKoZaCzgqSs+Pw9BM1ZXXNvXOAzmLPBJaT+M0mc5xYrNS5cLp
gCrOa10CgYAnvKcqTzzGfLT0lguByEeCvpg+xGoE71yn6E0O+XEK1QOr+fB9OT8O
JHziHmuPQVY8TmM79+ZhK3kf6lv2R/KFcO+uCpFKGLAYHlNpa69/GFCKED0rz+3x
t/kt5vxMc9LJ3tzfK3qAKm8UC8PjPd84kI8J3eI9kNGyGgA4sIHuAA==
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
