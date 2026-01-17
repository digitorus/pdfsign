package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"io"

	"os"
	"path/filepath"

	"golang.org/x/crypto/ocsp"
)

// BytesReader implements io.ReaderAt for in-memory byte slices.
type BytesReader struct {
	Data []byte
}

func NewBytesReader(data []byte) *BytesReader {
	return &BytesReader{Data: data}
}

func (r *BytesReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r.Data)) {
		return 0, io.EOF
	}
	n = copy(p, r.Data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// KeyProfile defines the cryptographic settings for the PKI.
type KeyProfile string

const (
	RSA_2048   KeyProfile = "RSA_2048"
	RSA_3072   KeyProfile = "RSA_3072"
	RSA_4096   KeyProfile = "RSA_4096"
	ECDSA_P256 KeyProfile = "ECDSA_P256"
	ECDSA_P384 KeyProfile = "ECDSA_P384"
	ECDSA_P521 KeyProfile = "ECDSA_P521"
)

type TestPKIConfig struct {
	Profile         KeyProfile
	IntermediateCAs int
}

// TestPKI manages a temporary PKI hierarchy for testing.
type TestPKI struct {
	T                 *testing.T
	RootKey           crypto.Signer
	RootCert          *x509.Certificate
	IntermediateKeys  []crypto.Signer
	IntermediateCerts []*x509.Certificate
	Server            *httptest.Server
	CRLBytes          []byte
	Requests          int
	OCSPRequests      int
	FailOCSP          bool
	Profile           KeyProfile
}

// NewTestPKI creates a fresh Root CA and initializes the helper.
func NewTestPKI(t *testing.T) *TestPKI {
	return NewTestPKIWithConfig(t, TestPKIConfig{
		Profile:         ECDSA_P384,
		IntermediateCAs: 1,
	})
}

// NewTestPKIWithConfig allows detailed configuration of the PKI.
func NewTestPKIWithConfig(t *testing.T, config TestPKIConfig) *TestPKI {
	// 1. Generate Root Key
	rootKey := GenerateKey(t, config.Profile)

	// 2. Generate Root Certificate (Self-Signed)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "PDFSign Test Root CA",
			Organization: []string{"PDFSign Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		Fail(t, "failed to create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		Fail(t, "failed to parse root cert: %v", err)
	}

	// 3. Generate Intermediate Chain
	var intermediateKeys []crypto.Signer
	var intermediateCerts []*x509.Certificate

	parentKey := rootKey
	parentCert := rootCert

	for i := 0; i < config.IntermediateCAs; i++ {
		key := GenerateKey(t, config.Profile)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("PDFSign Test Intermediate CA %d", i+1),
				Organization: []string{"PDFSign Test Org"},
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			SubjectKeyId:          []byte{5, 6, 7, 8, byte(i)},
			AuthorityKeyId:        parentCert.SubjectKeyId,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, key.Public(), parentKey)
		if err != nil {
			Fail(t, "failed to create intermediate cert %d: %v", i, err)
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			Fail(t, "failed to parse intermediate cert %d: %v", i, err)
		}

		intermediateKeys = append(intermediateKeys, key)
		intermediateCerts = append(intermediateCerts, cert)

		parentKey = key
		parentCert = cert
	}

	return &TestPKI{
		T:                 t,
		RootKey:           rootKey,
		RootCert:          rootCert,
		IntermediateKeys:  intermediateKeys,
		IntermediateCerts: intermediateCerts,
		Profile:           config.Profile,
	}
}

// StartCRLServer generates a valid CRL and starts a mock HTTP server serving it.
func (p *TestPKI) StartCRLServer() {
	if len(p.IntermediateCerts) == 0 {
		return
	}
	lastIdx := len(p.IntermediateCerts) - 1
	issuerCert := p.IntermediateCerts[lastIdx]
	issuerKey := p.IntermediateKeys[lastIdx]

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(9999),
			RevocationTime: time.Now(),
		},
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
		RevokedCertificates: revokedCerts,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		Fail(p.T, "failed to create CRL: %v", err)
	}
	p.CRLBytes = crlBytes

	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crl" {
			p.Requests++
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(p.CRLBytes)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ocsp") {
			p.OCSPRequests++

			if p.FailOCSP {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			parts := strings.Split(r.URL.Path, "/")
			if len(parts) < 3 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			b64Req := parts[len(parts)-1]

			reqBytes, err := base64.StdEncoding.DecodeString(b64Req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ocspReq, err := ocsp.ParseRequest(reqBytes)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			now := time.Now()
			template := ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: ocspReq.SerialNumber,
				ThisUpdate:   now.Add(-1 * time.Hour),
				NextUpdate:   now.Add(24 * time.Hour),
			}

			issuerCert := p.IntermediateCerts[len(p.IntermediateCerts)-1]
			respBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, template, p.IntermediateKeys[len(p.IntermediateKeys)-1])
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(respBytes)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ca") {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			if len(p.IntermediateCerts) > 0 {
				_, _ = w.Write(p.IntermediateCerts[len(p.IntermediateCerts)-1].Raw)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// IssueLeaf generates a new leaf certificate signed by the Root CA.
func (p *TestPKI) IssueLeaf(commonName string) (crypto.Signer, *x509.Certificate) {
	if p.Server == nil {
		Fail(p.T, "StartCRLServer() must be called before IssueLeaf")
	}

	priv := GenerateKey(p.T, p.Profile)

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PDFSign Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}},
		CRLDistributionPoints: []string{fmt.Sprintf("%s/crl", p.Server.URL)},
		OCSPServer:            []string{fmt.Sprintf("%s/ocsp", p.Server.URL)},
		IssuingCertificateURL: []string{fmt.Sprintf("%s/ca", p.Server.URL)},
	}

	var issuerCert *x509.Certificate
	var issuerKey crypto.Signer

	if len(p.IntermediateCerts) > 0 {
		issuerCert = p.IntermediateCerts[len(p.IntermediateCerts)-1]
		issuerKey = p.IntermediateKeys[len(p.IntermediateKeys)-1]
	} else {
		issuerCert = p.RootCert
		issuerKey = p.RootKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		Fail(p.T, "failed to issue leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		Fail(p.T, "failed to parse leaf cert: %v", err)
	}

	return priv, leafCert
}

// Chain returns the certificate chain for a leaf (Intermediate -> Root).
func (p *TestPKI) Chain() []*x509.Certificate {
	var chain []*x509.Certificate
	for i := len(p.IntermediateCerts) - 1; i >= 0; i-- {
		chain = append(chain, p.IntermediateCerts[i])
	}
	chain = append(chain, p.RootCert)
	return chain
}

// Close stops the mock server.
func (p *TestPKI) Close() {
	if p.Server != nil {
		p.Server.Close()
	}
}

func Fail(t *testing.T, format string, args ...interface{}) {
	if t != nil {
		t.Fatalf(format, args...)
	} else {
		log.Fatalf(format, args...)
	}
}

func GenerateKey(t *testing.T, profile KeyProfile) crypto.Signer {
	switch profile {
	case RSA_2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			Fail(t, "failed to generate RSA 2048 key: %v", err)
		}
		return k
	case RSA_3072:
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			Fail(t, "failed to generate RSA 3072 key: %v", err)
		}
		return k
	case RSA_4096:
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			Fail(t, "failed to generate RSA 4096 key: %v", err)
		}
		return k
	case ECDSA_P256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			Fail(t, "failed to generate P-256 key: %v", err)
		}
		return k
	case ECDSA_P384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			Fail(t, "failed to generate P-384 key: %v", err)
		}
		return k
	case ECDSA_P521:
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			Fail(t, "failed to generate P-521 key: %v", err)
		}
		return k
	default:
		Fail(t, "unknown key profile: %s", profile)
		return nil
	}
}

// LoadBenchKeys returns a pre-defined certificate and private key for benchmarking.
func LoadBenchKeys() (*x509.Certificate, crypto.Signer) {
	certPem := `-----BEGIN CERTIFICATE-----
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

	keyPem := `-----BEGIN RSA PRIVATE KEY-----
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

	certBlock, _ := pem.Decode([]byte(certPem))
	parsedCert, _ := x509.ParseCertificate(certBlock.Bytes)

	keyBlock, _ := pem.Decode([]byte(keyPem))
	parsedKey, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	return parsedCert, parsedKey
}

// GetTestFile finds the path to a test file by walking up the directory tree.
func GetTestFile(path string) string {
	// If path is already absolute or starts with ../, return as is
	if filepath.IsAbs(path) {
		return path
	}

	// Try current directory
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// Walk up searching for 'testfiles'
	cwd, _ := os.Getwd()
	maxDepth := 5
	for i := 0; i < maxDepth; i++ {
		target := filepath.Join(cwd, "testfiles")
		if _, err := os.Stat(target); err == nil {
			return filepath.Join(cwd, path)
		}
		cwd = filepath.Dir(cwd)
		if cwd == "/" || cwd == "." {
			break
		}
	}

	return path
}
