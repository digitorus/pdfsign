package sign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"
	"github.com/mattetti/filebuffer"
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

func loadCertificateAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		t.Fatalf("failed to parse PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		t.Fatalf("failed to parse PEM block containing the private key")
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	return cert, pkey
}

func verifySignedFile(t *testing.T, tmpfile *os.File, originalFileName string) {
	_, err := verify.VerifyFile(tmpfile)
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())

		err2 := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName)
		if err2 != nil {
			t.Error(err2)
		}
	}
}

func TestReaderCanReadPDF(t *testing.T) {
	files, err := os.ReadDir("../testfiles")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}

		t.Run(f.Name(), func(st *testing.T) {
			st.Parallel()

			input_file, err := os.Open("../testfiles/" + f.Name())
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
			defer func() {
				if err := input_file.Close(); err != nil {
					st.Errorf("Failed to close input_file: %v", err)
				}
			}()

			finfo, err := input_file.Stat()
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
			size := finfo.Size()

			_, err = pdf.NewReader(input_file, size)
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
		})
	}
}

func TestMain(m *testing.M) {
	_ = os.RemoveAll("../testfiles/failed/")
	_ = os.MkdirAll("../testfiles/failed/", 0o777)
	_ = os.RemoveAll("../testfiles/success/")
	_ = os.MkdirAll("../testfiles/success/", 0o777)

	os.Exit(m.Run())
}

func testSignAllFiles(t *testing.T, baseSignData SignData) {
	files, err := os.ReadDir("../testfiles/")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	cert, pkey := loadCertificateAndKey(t)

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}

		t.Run(f.Name(), func(st *testing.T) {
			ext := filepath.Ext(f.Name())
			outputName := f.Name()[:len(f.Name())-len(ext)] + "_" + t.Name() + ext
			var outputFile *os.File
			var err error

			if testing.Verbose() {
				outputFile, err = os.Create(filepath.Join("../testfiles/success", outputName))
			} else {
				outputFile, err = os.CreateTemp("", fmt.Sprintf("%s_%s_", t.Name(), f.Name()))
			}

			if err != nil {
				st.Fatalf("%s", err.Error())
			}

			defer func() {
				if !testing.Verbose() {
					_ = os.Remove(outputFile.Name())
				}
			}()

			signData := baseSignData
			signData.Signer = pkey
			signData.Certificate = cert

			err = SignFile("../testfiles/"+f.Name(), outputFile.Name(), signData)
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
			verifySignedFile(st, outputFile, outputName)
		})
	}
}

func TestSignPDF(t *testing.T) {
	testSignAllFiles(t, SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		TSA: TSA{
			URL: "http://timestamp.digicert.com",
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: DefaultEmbedRevocationStatusFunction,
	})
}

func TestSignPDFVisibleAll(t *testing.T) {
	testSignAllFiles(t, SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Visible Signature Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  400,
			LowerLeftY:  50,
			UpperRightX: 600,
			UpperRightY: 125,
		},
	})
}

func TestSignPDFFileUTF8(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	signerName := "姓名"
	signerLocation := "位置"
	inputFilePath := "../testfiles/testfile20.pdf"
	originalFileName := filepath.Base(inputFilePath)

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        signerName,
				Location:    signerLocation,
				Reason:      "Test with UTF-8",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	info, err := verify.VerifyFile(tmpfile)
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
		if err := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName); err != nil {
			t.Error(err)
		}
	} else if len(info.Signers) == 0 {
		t.Fatalf("no signers found in %s", tmpfile.Name())
	} else {
		if info.Signers[0].Name != signerName {
			t.Fatalf("expected %q, got %q", signerName, info.Signers[0].Name)
		}
		if info.Signers[0].Location != signerLocation {
			t.Fatalf("expected %q, got %q", signerLocation, info.Signers[0].Location)
		}
	}
}

func BenchmarkSignPDF(b *testing.B) {
	cert, pkey := loadCertificateAndKey(&testing.T{})
	certificateChains := [][]*x509.Certificate{}

	data, err := os.ReadFile("../testfiles/testfile20.pdf")
	if err != nil {
		b.Fatalf("%s", err.Error())
	}

	inputFile := filebuffer.New(data)
	size := int64(len(data))

	rdr, err := pdf.NewReader(inputFile, size)
	if err != nil {
		b.Fatalf("%s: %s", "testfile20.pdf", err.Error())
	}

	for n := 0; n < b.N; n++ {
		if _, err := inputFile.Seek(0, 0); err != nil {
			b.Fatalf("%s: %s", "testfile20.pdf", err.Error())
		}

		err = Sign(inputFile, io.Discard, rdr, size, SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        "John Doe",
					Location:    "Somewhere",
					Reason:      "Test",
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   CertificationSignature,
				DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
			},
			Signer:            pkey,
			Certificate:       cert,
			CertificateChains: certificateChains,
			RevocationData:    revocation.InfoArchival{},
		})
		if err != nil {
			b.Fatalf("%s: %s", "testfile20.pdf", err.Error())
		}
	}
}

func TestSignPDFWithTwoApproval(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	tbsFile := "../testfiles/testfile20.pdf"

	for i := 1; i <= 2; i++ {
		approvalTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_%d_", t.Name(), i))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}
		defer func() {
			if err := os.Remove(approvalTMPFile.Name()); err != nil {
				t.Errorf("Failed to remove approvalTMPFile: %v", err)
			}
		}()

		err = SignFile(tbsFile, approvalTMPFile.Name(), SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        fmt.Sprintf("Jane %d Doe", i),
					Location:    "Anywhere",
					Reason:      fmt.Sprintf("Approval Signature %d", i),
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   ApprovalSignature,
				DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
			},
			DigestAlgorithm: crypto.SHA512,
			Signer:          pkey,
			Certificate:     cert,
		})
		if err != nil {
			t.Fatalf("%s: %s", "testfile20.pdf", err.Error())
		}

		verifySignedFile(t, approvalTMPFile, filepath.Base(tbsFile))
		tbsFile = approvalTMPFile.Name()
	}
}

func TestSignPDFWithCertificationApprovalAndTimeStamp(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	tbsFile := "../testfiles/testfile20.pdf"

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile(tbsFile, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Certification Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", filepath.Base(tbsFile), err.Error())
	}

	verifySignedFile(t, tmpfile, filepath.Base(tbsFile))
	tbsFile = tmpfile.Name()

	for i := 1; i <= 2; i++ {
		approvalTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_approval_%d_", t.Name(), i))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}
		defer func() {
			if err := os.Remove(approvalTMPFile.Name()); err != nil {
				t.Errorf("Failed to remove approvalTMPFile: %v", err)
			}
		}()

		err = SignFile(tbsFile, approvalTMPFile.Name(), SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        fmt.Sprintf("Jane %d Doe", i),
					Location:    "Anywhere",
					Reason:      fmt.Sprintf("Approval Signature %d", i),
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   ApprovalSignature,
				DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
			},
			DigestAlgorithm: crypto.SHA512,
			Signer:          pkey,
			Certificate:     cert,
		})
		if err != nil {
			t.Fatalf("%s: %s", filepath.Base(tbsFile), err.Error())
		}

		verifySignedFile(t, approvalTMPFile, filepath.Base(tbsFile))
		tbsFile = approvalTMPFile.Name()
	}

	timeStampTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_timestamp_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(timeStampTMPFile.Name()); err != nil {
			t.Errorf("Failed to remove timeStampTMPFile: %v", err)
		}
	}()

	err = SignFile(tbsFile, timeStampTMPFile.Name(), SignData{
		Signature: SignDataSignature{
			CertType: TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: TSA{
			URL: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
		},
	})
	if err != nil {
		t.Fatalf("%s: %s", filepath.Base(tbsFile), err.Error())
	}
	verifySignedFile(t, timeStampTMPFile, "testfile20.pdf")
}

func TestTimestampPDFFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			CertType: TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: TSA{
			URL: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
		},
	})
	if err != nil {
		t.Fatalf("%s: %s", "testfile20.pdf", err.Error())
	}

	verifySignedFile(t, tmpfile, "testfile20.pdf")
}

// TestSignPDFWithImage tests signing a PDF with an image in the signature
func TestSignPDFWithImage(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/pdfsign-signature.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  400,
			LowerLeftY:  50,
			UpperRightX: 600,
			UpperRightY: 125,
			Image:       signatureImage, // Use the signature image
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	verifySignedFile(t, tmpfile, originalFileName)
}

// TestSignPDFWithTwoImages tests signing a PDF with two different signatures with images
func TestSignPDFWithTwoImages(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	tbsFile := "../testfiles/testfile12.pdf"

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/pdfsign-signature.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	// First signature
	firstSignature, err := os.CreateTemp("", fmt.Sprintf("%s_first_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(firstSignature.Name()); err != nil {
			t.Errorf("Failed to remove firstSignature: %v", err)
		}
	}()

	err = SignFile(tbsFile, firstSignature.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "First signature with image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  50,
			LowerLeftY:  50,
			UpperRightX: 250,
			UpperRightY: 125,
			Image:       signatureImage,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("First signature failed: %s", err.Error())
	}

	verifySignedFile(t, firstSignature, filepath.Base(tbsFile))

	// Second signature
	secondSignature, err := os.CreateTemp("", fmt.Sprintf("%s_second_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(secondSignature.Name()); err != nil {
			t.Errorf("Failed to remove secondSignature: %v", err)
		}
	}()

	err = SignFile(firstSignature.Name(), secondSignature.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "Jane Doe",
				Location:    "Elsewhere",
				Reason:      "Second signature with image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  300,
			LowerLeftY:  50,
			UpperRightX: 500,
			UpperRightY: 125,
			Image:       signatureImage,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("Second signature failed: %s", err.Error())
	}

	verifySignedFile(t, secondSignature, filepath.Base(tbsFile))
}

// TestSignPDFWithWatermarkImageJPG tests signing a PDF with a JPG image and text above
func TestSignPDFWithWatermarkImageJPG(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/pdfsign-signature-watermark.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "James SuperSmith",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and watermark image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:          true,
			LowerLeftX:       400,
			LowerLeftY:       50,
			UpperRightX:      600,
			UpperRightY:      125,
			Image:            signatureImage, // Use the signature image
			ImageAsWatermark: true,           // Set the image as a watermark
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	verifySignedFile(t, tmpfile, originalFileName)
}

// TestSignPDFWithWatermarkImage tests signing a PDF with a PNG image and text above
func TestSignPDFWithWatermarkImagePNG(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/pdfsign-signature-watermark.png")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "James SuperSmith",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and watermark image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:          true,
			LowerLeftX:       400,
			LowerLeftY:       50,
			UpperRightX:      600,
			UpperRightY:      125,
			Image:            signatureImage, // Use the signature image
			ImageAsWatermark: true,           // Set the image as a watermark
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	verifySignedFile(t, tmpfile, originalFileName)
}

func TestVisualSignLastPage(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile16.pdf"
	input_file, err := os.Open(inputFilePath)
	originalFileName := filepath.Base(inputFilePath)
	if err != nil {
		t.Fail()
	}
	defer func() {
		if err := input_file.Close(); err != nil {
			t.Errorf("Failed to close input_file: %v", err)
		}
	}()

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fail()
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
	}()

	finfo, err := input_file.Stat()
	if err != nil {
		t.Fail()
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		t.Fail()
	}
	lastPage := rdr.NumPage()
	t.Logf("pdf total pages: %d", lastPage)
	err = Sign(input_file, tmpfile, rdr, size, SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere on the globe",
				Reason:      "My season for signing this document",
				ContactInfo: "How you like",
				Date:        time.Now().Local(),
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:          pkey,          // crypto.Signer
		DigestAlgorithm: crypto.SHA256, // hash algorithm for the digest creation
		Certificate:     cert,          // x509.Certificate
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  400,
			LowerLeftY:  50,
			UpperRightX: 600,
			UpperRightY: 125,
			Page:        uint32(lastPage),
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: DefaultEmbedRevocationStatusFunction,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifySignedFile(t, tmpfile, originalFileName)
}

// TestRetryMechanismProducesValidPDF tests that when a retry is triggered
// (due to undersized buffer), the resulting PDF is still valid.
// This is a regression test for a bug where retry would corrupt PDFs because
// context state (newXrefEntries, lastXrefID, etc.) wasn't reset between attempts.
func TestRetryMechanismProducesValidPDF(t *testing.T) {
	// Capture log output to verify retry happens
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	// Generate RSA-4096 key - produces 512-byte signatures
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate RSA-4096 key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Retry Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	inputFilePath := "../testfiles/testfile20.pdf"
	tmpfile, err := os.CreateTemp("", "retry_test_*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	// Force a retry by setting SignatureSizeOverride to simulate the old bug.
	// Old bug: used Certificate.SignatureAlgorithm (SHA256=256 bits) instead of key size.
	// RSA-4096 produces 512-byte signatures, but old code would allocate for 256 bytes.
	// This override replicates that bug to test the retry mechanism.
	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:   "Retry Test",
				Reason: "Testing retry mechanism with undersized buffer",
				Date:   time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:                privateKey,
		DigestAlgorithm:       crypto.SHA256,
		Certificate:           cert,
		SignatureSizeOverride: 1, // Way too small! RSA-4096 needs 512 bytes. Forces retry.
	})
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	// Verify retry actually happened
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Signature too long") {
		t.Logf("Log output: %s", logOutput)
		t.Fatal("Expected retry to be triggered but no retry log message found")
	}
	t.Logf("Retry was triggered: %s", logOutput)

	// Verify the PDF is valid - this will fail if retry corrupted the PDF
	_, err = verify.VerifyFile(tmpfile)
	if err != nil {
		// Debug: show file size and content around signature
		_, _ = tmpfile.Seek(0, 0)
		data, _ := io.ReadAll(tmpfile)
		t.Logf("Output file size: %d bytes", len(data))

		// Find /Contents< to see signature area
		contentsIdx := bytes.Index(data, []byte("/Contents<"))
		if contentsIdx != -1 {
			start := contentsIdx
			end := contentsIdx + 200
			if end > len(data) {
				end = len(data)
			}
			t.Logf("Signature area at offset %d: %q", contentsIdx, data[start:end])
		} else {
			t.Log("Could not find /Contents<")
		}

		// Show area around offset 5209 where xref says object 11 is
		if len(data) > 5409 {
			t.Logf("Content at offset 5209: %q", data[5209:5409])
		}

		t.Fatalf("PDF verification failed after retry: %v", err)
	}
}

// TestSignatureSizeOverride tests that SignatureSizeOverride is used when set.
func TestSignatureSizeOverride(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, err := os.CreateTemp("", "sigsize_override_test_*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	// Test with a valid override (larger than needed)
	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:   "Override Test",
				Reason: "Testing SignatureSizeOverride",
				Date:   time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:                pkey,
		DigestAlgorithm:       crypto.SHA256,
		Certificate:           cert,
		SignatureSizeOverride: 512, // Override with larger size
	})
	if err != nil {
		t.Fatalf("failed to sign PDF with SignatureSizeOverride: %v", err)
	}

	verifySignedFile(t, tmpfile, "sigsize_override_test.pdf")
}

// TestSignatureSizeOverrideTooSmall tests that signing fails gracefully when
// SignatureSizeOverride is set too small.
func TestSignatureSizeOverrideTooSmall(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, err := os.CreateTemp("", "sigsize_small_test_*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	// Test with override that's too small - should trigger retry and eventually succeed
	// The embedded certificate is RSA-1024 (128 bytes), so 64 is too small
	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:   "Small Override Test",
				Reason: "Testing too-small SignatureSizeOverride",
				Date:   time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:                pkey,
		DigestAlgorithm:       crypto.SHA256,
		Certificate:           cert,
		SignatureSizeOverride: 64, // Too small - will trigger retry
	})

	// This should succeed because the retry mechanism will increase the buffer
	if err != nil {
		t.Fatalf("signing should have succeeded with retry, got error: %v", err)
	}

	verifySignedFile(t, tmpfile, "sigsize_small_test.pdf")
}

// TestSignPDFWithRSA3072Key tests signing with an RSA-3072 key.
// This is a regression test for a bug where the signature buffer size was
// calculated based on Certificate.SignatureAlgorithm (the algorithm used to
// sign the certificate) rather than the actual public key size.
//
// RSA-3072 produces 384-byte signatures, but a certificate signed with SHA256-RSA
// would cause the code to allocate only 256 bytes, triggering retry logic that
// could corrupt the PDF.
func TestSignPDFWithRSA3072Key(t *testing.T) {
	// Generate a 3072-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("failed to generate RSA-3072 key: %v", err)
	}

	// Create a self-signed certificate with SHA256-RSA signature algorithm
	// This is the key part: the certificate is signed with SHA256-RSA,
	// but the public key is RSA-3072 which produces 384-byte signatures
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "RSA-3072 Test Certificate",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Verify our test setup: certificate should be signed with SHA256-RSA
	// but have an RSA-3072 public key
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("expected SHA256WithRSA signature algorithm, got %v", cert.SignatureAlgorithm)
	}
	if privateKey.Size() != 384 { // 3072 bits = 384 bytes
		t.Fatalf("expected 384-byte key size, got %d", privateKey.Size())
	}

	// Now try to sign a PDF with this certificate
	inputFilePath := "../testfiles/testfile20.pdf"
	tmpfile, err := os.CreateTemp("", "rsa3072_test_*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "RSA-3072 Test",
				Location:    "Test Location",
				Reason:      "Testing RSA-3072 signature buffer size",
				ContactInfo: "test@example.com",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:             privateKey,
		DigestAlgorithm:    crypto.SHA256,
		Certificate:        cert,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: DefaultEmbedRevocationStatusFunction,
	})
	if err != nil {
		t.Fatalf("failed to sign PDF with RSA-3072 key: %v", err)
	}

	// Verify the signed PDF
	verifySignedFile(t, tmpfile, "rsa3072_test.pdf")
}
