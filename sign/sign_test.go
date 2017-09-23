package sign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bitbucket.org/digitorus/pdf"
	"bitbucket.org/digitorus/pdfsign/revocation"
)

const signCertPem = `-----BEGIN CERTIFICATE-----
MIIDBzCCAnCgAwIBAgIJAIJ/XyRx/DG0MA0GCSqGSIb3DQEBCwUAMIGZMQswCQYD
VQQGEwJOTDEVMBMGA1UECAwMWnVpZC1Ib2xsYW5kMRIwEAYDVQQHDAlSb3R0ZXJk
YW0xEjAQBgNVBAoMCVVuaWNvZGVyczELMAkGA1UECwwCSVQxGjAYBgNVBAMMEUpl
cm9lbiBCb2JiZWxkaWprMSIwIAYJKoZIhvcNAQkBFhNqZXJvZW5AdW5pY29kZXJz
Lm5sMCAXDTE3MDkxNzExMjkzNloYDzMwMTcwMTE4MTEyOTM2WjCBmTELMAkGA1UE
BhMCTkwxFTATBgNVBAgMDFp1aWQtSG9sbGFuZDESMBAGA1UEBwwJUm90dGVyZGFt
MRIwEAYDVQQKDAlVbmljb2RlcnMxCzAJBgNVBAsMAklUMRowGAYDVQQDDBFKZXJv
ZW4gQm9iYmVsZGlqazEiMCAGCSqGSIb3DQEJARYTamVyb2VuQHVuaWNvZGVycy5u
bDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmrvrZiUZZ/nSmFKMsQXg5slY
TQjj7nuenczt7KGPVuGA8nNOqiGktf+yep5h2r87jPvVjVXjJVjOTKx9HMhaFECH
KHKV72iQhlw4fXa8iB1EDeGuwP+pTpRWlzurQ/YMxvemNJVcGMfTE42X5Bgqh6Dv
kddRTAeeqQDBD6+5VPsCAwEAAaNTMFEwHQYDVR0OBBYEFETizi2bTLRMIknQXWDR
nQ59xI99MB8GA1UdIwQYMBaAFETizi2bTLRMIknQXWDRnQ59xI99MA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOHdI9f4I1rd7DjOXnT6IJl/4mIQ
kkaeZkjcsgdZAeW154vjDEr8sIdq+W15huWJKZkqwhn1sJLqSOlEhaYbJJNHVKc9
ZH5r6ujfc336AtjrjCL3OYHQQj05isKm9ii5IL/i+rlZ5xro/dJ91jnjqNVQPvso
oA4h5BVsLZPIYto=
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

func TestReaderCanReadPDF(t *testing.T) {
	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			fmt.Printf("Skipping file %s", f.Name())
			continue
		}

		input_file, err := os.Open("../testfiles/" + f.Name())
		if err != nil {
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}

		finfo, err := input_file.Stat()
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}
		size := finfo.Size()

		_, err = pdf.NewReader(input_file, size)
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}

		input_file.Close()
	}
}

func TestSignPDF(t *testing.T) {
	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		t.Errorf("failed to parse PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		t.Errorf("failed to parse PEM block containing the private key")
		return
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	certificate_chains := make([][]*x509.Certificate, 0)

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			fmt.Printf("Skipping file %s\n", f.Name())
			continue
		}

		fmt.Printf("Signing file %s\n", f.Name())

		err = SignFile("../testfiles/"+f.Name(), "../testfiles/"+f.Name()+".tmp", SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        "Jeroen Bobbeldijk",
					Location:    "Rotterdam",
					Reason:      "Test",
					ContactInfo: "Geen",
					Date:        time.Now().Local(),
				},
				CertType: 2,
				Approval: false,
			},
			Signer:            pkey,
			Certificate:       cert,
			CertificateChains: certificate_chains,
			TSA: TSA{
				URL: "http://aatl-timestamp.globalsign.com/tsa/aohfewat2389535fnasgnlg5m23",
			},
			RevocationData:     revocation.InfoArchival{},
			RevocationFunction: DefaultEmbedRevocationStatusFunction,
		})

		// Cleanup old files.
		defer os.Remove("../testfiles/"+f.Name()+".tmp")

		if err != nil {
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}
	}
}

func BenchmarkSignPDF(b *testing.B) {
	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		b.Errorf("failed to parse PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		b.Errorf("%s", err.Error())
		return
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		b.Errorf("failed to parse PEM block containing the private key")
		return
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		b.Errorf("%s", err.Error())
		return
	}

	certificate_chains := make([][]*x509.Certificate, 0)

	for n := 0; n < b.N; n++ {
		err := SignFile("../testfiles/benchmark.pdf", "../testfiles/benchmark.pdf.tmp", SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        "Jeroen Bobbeldijk",
					Location:    "Rotterdam",
					Reason:      "Test",
					ContactInfo: "Geen",
					Date:        time.Now().Local(),
				},
				CertType: 2,
				Approval: false,
			},
			Signer:            pkey,
			Certificate:       cert,
			CertificateChains: certificate_chains,
			TSA: TSA{
				URL: "http://aatl-timestamp.globalsign.com/tsa/aohfewat2389535fnasgnlg5m23",
			},
			RevocationData:     revocation.InfoArchival{},
			RevocationFunction: DefaultEmbedRevocationStatusFunction,
		})

		os.Remove("../testfiles/benchmark.pdf.tmp")

		if err != nil {
			b.Errorf("%s: %s", "benchmark.pdf", err.Error())
			return
		}
	}
}
