package sign

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/digitorus/pdf"
	"github.com/mattetti/filebuffer"
	"github.com/subnoto/pdfsign/revocation"
	"github.com/subnoto/pdfsign/verify"
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

func TestSignPDF(t *testing.T) {
	_ = os.RemoveAll("../testfiles/failed/")
	_ = os.MkdirAll("../testfiles/failed/", 0o777)

	files, err := os.ReadDir("../testfiles/")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	cert, pkey := loadCertificateAndKey(t)
	certificateChains := [][]*x509.Certificate{}

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}

		t.Run(f.Name(), func(st *testing.T) {
			outputFile, err := os.CreateTemp("", fmt.Sprintf("%s_%s_", t.Name(), f.Name()))
			if err != nil {
				st.Fatalf("%s", err.Error())
			}
			defer func() {
				if err := os.Remove(outputFile.Name()); err != nil {
					st.Errorf("Failed to remove output file: %v", err)
				}
			}()

			_, err = SignFile("../testfiles/"+f.Name(), outputFile.Name(), SignData{
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
				TSA: TSA{
					URL: "http://timestamp.digicert.com",
				},
				RevocationData:     revocation.InfoArchival{},
				RevocationFunction: DefaultEmbedRevocationStatusFunction,
			})
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
			verifySignedFile(st, outputFile, filepath.Base(f.Name()))
		})
	}
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

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
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
	} else if len(info.Signatures) == 0 {
		t.Fatalf("no signatures found in %s", tmpfile.Name())
	} else {
		if info.Signatures[0].Info.Name != signerName {
			t.Fatalf("expected %q, got %q", signerName, info.Signatures[0].Info.Name)
		}
		if info.Signatures[0].Info.Location != signerLocation {
			t.Fatalf("expected %q, got %q", signerLocation, info.Signatures[0].Info.Location)
		}
	}
}

func TestSignPDFInitials(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)

	tests := []struct {
		name             string
		uid              string // UID is already in hex as present in testfile50
		signerName       string
		expectedInitials string
	}{
		{"jane", "6a616e652e736d697468406578616d706c652e636f6d", "Jane Smith", "JS"},
		{"newt", "6e657740746f746f2e636f6d", "Newt Totoo", "NT"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(st *testing.T) {
			st.Parallel()

			inputFilePath := "../testfiles/testfile50.pdf"
			tmpfile, err := os.CreateTemp("", "sign_initials_")
			if err != nil {
				st.Fatalf("failed to create tmpfile: %v", err)
			}
			defer func() {
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
				Signature: SignDataSignature{
					Info: SignDataSignatureInfo{
						Name: tc.signerName,
						Date: time.Now().Local(),
					},
					CertType:   CertificationSignature,
					DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
				},
				Signer:      pkey,
				Certificate: cert,
				Appearance: Appearance{
					SignerUID: tc.uid,
				},
			})
			if err != nil {
				st.Fatalf("sign failed: %v", err)
			}

			// Open signed file and verify AcroForm fields for the uid were updated
			sf, err := os.Open(tmpfile.Name())
			if err != nil {
				st.Fatalf("failed to open signed file: %v", err)
			}
			defer sf.Close()
			sfi, err := sf.Stat()
			if err != nil {
				st.Fatalf("stat failed: %v", err)
			}
			rdr, err := pdf.NewReader(sf, sfi.Size())
			if err != nil {
				st.Fatalf("pdf reader failed: %v", err)
			}

			acro := rdr.Trailer().Key("Root").Key("AcroForm")
			if acro.IsNull() {
				st.Fatalf("signed PDF missing AcroForm")
			}
			fields := acro.Key("Fields")
			if fields.IsNull() {
				st.Fatalf("signed PDF AcroForm missing Fields")
			}

			found := false
			for i := 0; i < fields.Len(); i++ {
				field := fields.Index(i)
				tVal := field.Key("T")
				if tVal.IsNull() {
					continue
				}
				fieldName := tVal.RawString()

				// Decode UTF-16 field names just like fillInitialsFields does
				decodedFieldName := fieldName
				b := []byte(fieldName)
				if len(b) >= 2 {
					// BOM 0xFEFF = big endian, 0xFFFE = little endian
					if b[0] == 0xfe && b[1] == 0xff {
						// UTF-16 BE
						var u16s []uint16
						for i := 2; i+1 < len(b); i += 2 {
							u16s = append(u16s, uint16(b[i])<<8|uint16(b[i+1]))
						}
						decodedFieldName = string(utf16.Decode(u16s))
					} else if b[0] == 0xff && b[1] == 0xfe {
						// UTF-16 LE
						var u16s []uint16
						for i := 2; i+1 < len(b); i += 2 {
							u16s = append(u16s, uint16(b[i])|uint16(b[i+1])<<8)
						}
						decodedFieldName = string(utf16.Decode(u16s))
					}
				}

				if !strings.Contains(decodedFieldName, tc.uid) {
					continue
				}
				vVal := field.Key("V")
				if vVal.IsNull() {
					continue
				}
				raw := vVal.RawString()
				if strings.Contains(raw, tc.expectedInitials) {
					found = true
					break
				}
			}

			if !found {
				st.Fatalf("expected initials %s for uid %s not found in any AcroForm field", tc.expectedInitials, tc.uid)
			}
		})
	}
}

func TestSignPDFVisible(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile12.pdf"
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

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test with visible signature",
				ContactInfo: "None",
			},
			CertType:   ApprovalSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: Appearance{
			Visible:     true,
			LowerLeftX:  350,
			LowerLeftY:  75,
			UpperRightX: 600,
			UpperRightY: 100,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	_, err = verify.VerifyFile(tmpfile)
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
		if err := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName); err != nil {
			t.Error(err)
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

		_, err = Sign(inputFile, io.Discard, rdr, size, SignData{
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

		_, err = SignFile(tbsFile, approvalTMPFile.Name(), SignData{
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

	_, err = SignFile(tbsFile, tmpfile.Name(), SignData{
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

		_, err = SignFile(tbsFile, approvalTMPFile.Name(), SignData{
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

	_, err = SignFile(tbsFile, timeStampTMPFile.Name(), SignData{
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

	_, err = SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), SignData{
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

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
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

	_, err = SignFile(tbsFile, firstSignature.Name(), SignData{
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

	_, err = SignFile(firstSignature.Name(), secondSignature.Name(), SignData{
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

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
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

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
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

// TestSignPDFAcroFormPreserved ensures signing a PDF with AcroForm does not
// remove existing form fields; the signed PDF should have at least as many
// AcroForm fields as the original (usually original + signature field).
func TestSignPDFAcroFormPreserved(t *testing.T) {
	cert, pkey := loadCertificateAndKey(t)
	inputFilePath := "../testfiles/testfile40.pdf"

	// Open original file and read its AcroForm fields count
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		t.Skipf("test file not available: %v", err)
		return
	}
	defer func() { _ = inputFile.Close() }()

	finfo, err := inputFile.Stat()
	if err != nil {
		t.Fatalf("failed to stat input file: %v", err)
	}
	rdr, err := pdf.NewReader(inputFile, finfo.Size())
	if err != nil {
		t.Fatalf("failed to read input PDF: %v", err)
	}

	acro := rdr.Trailer().Key("Root").Key("AcroForm")
	if acro.IsNull() {
		t.Fatalf("input PDF does not contain an AcroForm")
	}

	origFields := acro.Key("Fields")
	origCount := 0
	if !origFields.IsNull() {
		origCount = origFields.Len()
	}

	// Sign the file to a temporary output
	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	_, err = SignFile(inputFilePath, tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "Test",
				Location:    "Here",
				Reason:      "Preserve AcroForm",
				ContactInfo: "None",
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		DigestAlgorithm:    crypto.SHA256,
		Signer:             pkey,
		Certificate:        cert,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: DefaultEmbedRevocationStatusFunction,
	})
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	// Open signed file and check AcroForm fields
	signedFile, err := os.Open(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to open signed file: %v", err)
	}
	defer func() { _ = signedFile.Close() }()

	sfinfo, err := signedFile.Stat()
	if err != nil {
		t.Fatalf("failed to stat signed file: %v", err)
	}

	signedRdr, err := pdf.NewReader(signedFile, sfinfo.Size())
	if err != nil {
		t.Fatalf("failed to read signed PDF: %v", err)
	}

	sacro := signedRdr.Trailer().Key("Root").Key("AcroForm")
	if sacro.IsNull() {
		t.Fatalf("signed PDF missing AcroForm")
	}
	sfields := sacro.Key("Fields")
	if sfields.IsNull() {
		t.Fatalf("signed PDF AcroForm missing Fields")
	}
	newCount := sfields.Len()

	if newCount < origCount {
		t.Fatalf("AcroForm fields decreased after signing: before=%d after=%d", origCount, newCount)
	}

	verifySignedFile(t, tmpfile, filepath.Base(inputFilePath))
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
	_, err = Sign(input_file, tmpfile, rdr, size, SignData{
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

func TestSignVerifyHashConsistency(t *testing.T) {
	// Load test certificate and key
	cert, pkey := loadCertificateAndKey(t)
	certificateChains := [][]*x509.Certificate{}

	// Create a temporary output file for the signed PDF
	outputFile, err := os.CreateTemp("", "test_sign_verify_hash_*.pdf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(outputFile.Name()); err != nil {
			t.Errorf("Failed to remove output file: %v", err)
		}
	}()
	if err := outputFile.Close(); err != nil {
		t.Errorf("Failed to close output file: %v", err)
	}

	// Sign the PDF and get signature info
	signatureInfo, err := SignFile("../testfiles/testfile20.pdf", outputFile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "Test Signer",
				Location:    "Test Location",
				Reason:      "Hash consistency test",
				ContactInfo: "test@example.com",
				Date:        time.Now(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            pkey,
		Certificate:       cert,
		CertificateChains: certificateChains,
		DigestAlgorithm:   crypto.SHA256,
	})

	if err != nil {
		t.Fatalf("Failed to sign PDF: %v", err)
	}

	if signatureInfo == nil {
		t.Fatal("SignatureInfo should not be nil")
	}

	// Log signing results
	t.Logf("Sign results:")
	t.Logf("  Document Hash: %s", signatureInfo.DocumentHash)
	t.Logf("  Signature Hash: %s", signatureInfo.SignatureHash)

	// Now verify the signed PDF using the verify package
	signedFile, err := os.Open(outputFile.Name())
	if err != nil {
		t.Fatalf("Failed to open signed PDF: %v", err)
	}
	defer func() {
		if err := signedFile.Close(); err != nil {
			t.Errorf("Failed to close signed file: %v", err)
		}
	}()

	// Create verify options that allow untrusted roots since we're using a test certificate
	verifyOptions := verify.DefaultVerifyOptions()
	verifyOptions.AllowUntrustedRoots = true

	verifyResponse, err := verify.VerifyFileWithOptions(signedFile, verifyOptions)
	if err != nil {
		t.Fatalf("Failed to verify signed PDF: %v", err)
	}

	if verifyResponse == nil {
		t.Fatal("Verify response should not be nil")
	}

	if len(verifyResponse.Signatures) == 0 {
		t.Fatal("No signatures found during verification")
	}

	// Compare hashes from sign and verify operations
	verifyInfo := verifyResponse.Signatures[0].Info

	// Log verification results
	t.Logf("Verify results:")
	t.Logf("  Document Hash: %s", verifyInfo.DocumentHash)
	t.Logf("  Signature Hash: %s", verifyInfo.SignatureHash)

	// Document hash comparison - THIS IS CRITICAL and must match
	if signatureInfo.DocumentHash != verifyInfo.DocumentHash {
		t.Errorf("Document hash mismatch - this indicates a serious integrity issue:\n  Sign:   %s\n  Verify: %s",
			signatureInfo.DocumentHash, verifyInfo.DocumentHash)
	}

	// Signature hash comparison - comparing how sign vs verify compute signature hashes
	if signatureInfo.SignatureHash != verifyInfo.SignatureHash {
		t.Logf("Signature hash difference (may need further investigation):\n  Sign:   %s\n  Verify: %s",
			signatureInfo.SignatureHash, verifyInfo.SignatureHash)
	} else {
		t.Logf("✅ Signature hashes match: %s", signatureInfo.SignatureHash)
	}

	// Hash algorithm comparison (normalize case)
	signAlg := strings.ToLower(signatureInfo.HashAlgorithm)
	verifyAlg := strings.ToLower(verifyInfo.HashAlgorithm)

	// The sign function returns "SHA-256" while verify might return "sha256"
	if signAlg == "sha-256" {
		signAlg = "sha256"
	}
	if verifyAlg == "sha-256" {
		verifyAlg = "sha256"
	}

	if signAlg != verifyAlg {
		t.Errorf("Hash algorithm mismatch:\n  Sign:   %s\n  Verify: %s",
			signatureInfo.HashAlgorithm, verifyInfo.HashAlgorithm)
	}

	// Log success for document hash (the critical check)
	if signatureInfo.DocumentHash == verifyInfo.DocumentHash && signAlg == verifyAlg {
		t.Logf("✅ Critical integrity check passed:")
		t.Logf("  Document Hash: %s (matches between sign and verify)", signatureInfo.DocumentHash)
		t.Logf("  Hash Algorithm: %s (sign) / %s (verify)", signatureInfo.HashAlgorithm, verifyInfo.HashAlgorithm)
	}

	// Also verify that signature info fields match
	if signatureInfo.Name != verifyInfo.Name {
		t.Errorf("Name mismatch: sign='%s', verify='%s'", signatureInfo.Name, verifyInfo.Name)
	}

	if signatureInfo.Location != verifyInfo.Location {
		t.Errorf("Location mismatch: sign='%s', verify='%s'", signatureInfo.Location, verifyInfo.Location)
	}

	if signatureInfo.Reason != verifyInfo.Reason {
		t.Errorf("Reason mismatch: sign='%s', verify='%s'", signatureInfo.Reason, verifyInfo.Reason)
	}

	if signatureInfo.ContactInfo != verifyInfo.ContactInfo {
		t.Errorf("ContactInfo mismatch: sign='%s', verify='%s'", signatureInfo.ContactInfo, verifyInfo.ContactInfo)
	}
}
