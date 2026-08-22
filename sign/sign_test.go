package sign_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	// Registers MD5 so the weak-digest test hits validation, not the fallback.
	_ "crypto/md5"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/mattetti/filebuffer"
)

func verifySignedFile(t *testing.T, tmpfile *os.File, originalFileName string) {
	doc, err := pdfsign.OpenFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
	}

	vRes := doc.Verify().TrustSelfSigned(true)
	if err := vRes.Err(); err != nil {
		t.Fatalf("%s: verification failed: %v", tmpfile.Name(), err)
		err2 := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName)
		if err2 != nil {
			t.Error(err2)
		}
	}

	if vRes.Count() == 0 {
		t.Fatalf("%s: no signers found", tmpfile.Name())
		err2 := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName)
		if err2 != nil {
			t.Error(err2)
		}
	}

	// Fail if signatures are not valid
	if !vRes.Valid() {
		for _, sig := range vRes.Signatures() {
			if len(sig.Errors) > 0 {
				t.Errorf("%s: signature error: %v", tmpfile.Name(), sig.Errors)
				err2 := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName)
				if err2 != nil {
					t.Error(err2)
				}
			}
		}
	} else {
		err2 := os.Rename(tmpfile.Name(), "../testfiles/success/"+originalFileName)
		if err2 != nil {
			t.Error(err2)
		}
	}
}

func verifyIntermediateFile(t *testing.T, tmpfile *os.File) {
	doc, err := pdfsign.OpenFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
	}

	vRes := doc.Verify().TrustSelfSigned(true)
	if err := vRes.Err(); err != nil {
		t.Fatalf("%s: verification failed: %v", tmpfile.Name(), err)
	}

	if vRes.Count() == 0 {
		t.Fatalf("%s: no signers found", tmpfile.Name())
	}
}

func TestCompatibilityFiles(t *testing.T) {
	files, err := os.ReadDir("../testfiles/compatibility/")
	if err != nil {
		t.Fatalf("Failed to read compatibility directory: %v", err)
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}

		t.Run(f.Name(), func(t *testing.T) {
			doc, err := pdfsign.OpenFile(filepath.Join("../testfiles/compatibility", f.Name()))
			if err != nil {
				t.Fatalf("%s: %s", f.Name(), err.Error())
			}

			// For compatibility files, we trust them (often untrusted roots in test env)
			vRes := doc.Verify().TrustSelfSigned(true)
			_ = vRes.Err() // We check individual signatures

			if vRes.Count() == 0 {
				t.Fatalf("No signatures found in %s", f.Name())
			}

			// We expect these might be "Valid" == false due to errors, so we check Errors list manually
			for _, sig := range vRes.Signatures() {
				// Special handling for testfile30.pdf (Adobe 2009 CRL v1)
				if f.Name() == "testfile30.pdf" {
					crlErrorFound := false
					for _, e := range sig.Errors {
						var revErr *verify.RevocationError
						if errors.As(e, &revErr) && revErr.Msg == "Failed to parse CRL: x509: unsupported crl version" {
							crlErrorFound = true
							continue // We expect and accept this error
						}
						// Fail on other errors
						t.Errorf("Unexpected error in %s: %v", f.Name(), e)
					}
					if !crlErrorFound {
						t.Log("Note: expected CRL error not found for testfile30.pdf (parser improved?)")
					}
				} else {
					// Fallback for other files not yet defined
					if len(sig.Errors) > 0 {
						t.Errorf("Unknown compatibility file %s has errors: %v", f.Name(), sig.Errors)
					}
				}
			}
		})
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

func testSignAllFiles(t *testing.T, baseSignData sign.SignData) {
	files, err := os.ReadDir("../testfiles/")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".pdf" {
			continue
		}
		if f.Name() == "testfile_multi.pdf" {
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

			err = sign.SignFile("../testfiles/"+f.Name(), outputFile.Name(), signData)
			if err != nil {
				st.Fatalf("%s: %s", f.Name(), err.Error())
			}
			verifySignedFile(st, outputFile, outputName)
		})
	}
}

func TestSignPDF(t *testing.T) {
	testSignAllFiles(t, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		TSA: sign.TSA{
			URL: testpki.StartMockTSA(t),
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
		DigestAlgorithm:    crypto.SHA512,
	})
}

func TestSignPDFVisibleAll(t *testing.T) {
	testSignAllFiles(t, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Visible Signature Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
			Visible:     true,
			LowerLeftX:  400,
			LowerLeftY:  50,
			UpperRightX: 600,
			UpperRightY: 125,
		},
		DigestAlgorithm: crypto.SHA512,
	})
}

func TestSignPDFFileUTF8(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	signerName := "姓名"
	signerLocation := "位置"
	inputFilePath := "../testfiles/testfile20.pdf"
	originalFileName := filepath.Base(inputFilePath)

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile(inputFilePath, tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        signerName,
				Location:    signerLocation,
				Reason:      "Test with UTF-8",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", originalFileName, err.Error())
	}

	doc, err := pdfsign.OpenFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
	}

	vRes := doc.Verify().TrustSelfSigned(true)
	if err := vRes.Err(); err != nil {
		t.Fatalf("%s: verification failed: %v", tmpfile.Name(), err)
		if err := os.Rename(tmpfile.Name(), "../testfiles/failed/"+originalFileName); err != nil {
			t.Error(err)
		}
	} else if vRes.Count() == 0 {
		t.Fatalf("no signers found in %s", tmpfile.Name())
	} else {
		sigs := vRes.Signatures()
		if sigs[0].SignerName != signerName {
			t.Fatalf("expected %q, got %q", signerName, sigs[0].SignerName)
		}
		if sigs[0].Location != signerLocation {
			t.Fatalf("expected %q, got %q", signerLocation, sigs[0].Location)
		}
	}
}

// TestSignPDF_ExtraSignedAttributes_AppearInPKCS7 verifies that
// caller-supplied custom signed attributes ride inside the
// cryptographically protected PKCS#7 SignedAttributes set so a
// downstream pkcs7.UnmarshalSignedAttribute can recover them by OID.
func TestSignPDF_ExtraSignedAttributes_AppearInPKCS7(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)

	// A test-only OID under the IANA "private experimental" arc.
	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	customValue := []byte("test content hash")

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	err = sign.SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "Extra Attrs Tester",
				Reason:      "Test ExtraSignedAttributes",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: customOID, Value: customValue},
		},
	})
	if err != nil {
		t.Fatalf("SignFile: %s", err.Error())
	}

	doc, err := pdfsign.OpenFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("%s: %s", tmpfile.Name(), err.Error())
	}

	var found bool
	for sig, err := range doc.Signatures() {
		if err != nil {
			t.Fatalf("signature iteration: %s", err.Error())
		}
		p7, err := pkcs7.Parse(sig.Contents())
		if err != nil {
			t.Fatalf("pkcs7.Parse: %s", err.Error())
		}

		var got []byte
		if err := p7.UnmarshalSignedAttribute(customOID, &got); err != nil {
			continue
		}
		if string(got) != string(customValue) {
			t.Fatalf("attribute value mismatch: want %q, got %q", customValue, got)
		}
		found = true
	}
	if !found {
		t.Fatal("custom signed attribute not found in any signature")
	}
}

func BenchmarkSignPDF(b *testing.B) {
	cert, pkey := sign.LoadCertificateAndKey(&testing.T{})
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

		err = sign.Sign(inputFile, io.Discard, rdr, size, sign.SignData{
			Signature: sign.SignDataSignature{
				Info: sign.SignDataSignatureInfo{
					Name:        "John Doe",
					Location:    "Somewhere",
					Reason:      "Test",
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   sign.CertificationSignature,
				DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
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
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	tbsFile := "../testfiles/testfile20.pdf"

	for i := 1; i <= 2; i++ {
		approvalTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_%d_", t.Name(), i))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}
		defer func() {
			_ = os.Remove(approvalTMPFile.Name())
		}()

		err = sign.SignFile(tbsFile, approvalTMPFile.Name(), sign.SignData{
			Signature: sign.SignDataSignature{
				Info: sign.SignDataSignatureInfo{
					Name:        fmt.Sprintf("Jane %d Doe", i),
					Location:    "Anywhere",
					Reason:      fmt.Sprintf("Approval Signature %d", i),
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   sign.ApprovalSignature,
				DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
			},
			DigestAlgorithm: crypto.SHA512,
			Signer:          pkey,
			Certificate:     cert,
		})
		if err != nil {
			t.Fatalf("%s: %s", "testfile20.pdf", err.Error())
		}

		if i < 2 {
			verifyIntermediateFile(t, approvalTMPFile)
		} else {
			verifySignedFile(t, approvalTMPFile, filepath.Base(tbsFile))
		}
		tbsFile = approvalTMPFile.Name()
	}
}

func TestSignPDFWithCertificationApprovalAndTimeStamp(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	tbsFile := "../testfiles/testfile20.pdf"

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile(tbsFile, tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Certification Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
		},
		DigestAlgorithm: crypto.SHA512,
		Signer:          pkey,
		Certificate:     cert,
	})
	if err != nil {
		t.Fatalf("%s: %s", filepath.Base(tbsFile), err.Error())
	}

	verifyIntermediateFile(t, tmpfile)
	tbsFile = tmpfile.Name()

	for i := 1; i <= 2; i++ {
		approvalTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_approval_%d_", t.Name(), i))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}
		defer func() {
			_ = os.Remove(approvalTMPFile.Name())
		}()

		err = sign.SignFile(tbsFile, approvalTMPFile.Name(), sign.SignData{
			Signature: sign.SignDataSignature{
				Info: sign.SignDataSignatureInfo{
					Name:        fmt.Sprintf("Jane %d Doe", i),
					Location:    "Anywhere",
					Reason:      fmt.Sprintf("Approval Signature %d", i),
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   sign.ApprovalSignature,
				DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms,
			},
			DigestAlgorithm: crypto.SHA512,
			Signer:          pkey,
			Certificate:     cert,
		})
		if err != nil {
			t.Fatalf("%s: %s", filepath.Base(tbsFile), err.Error())
		}

		verifyIntermediateFile(t, approvalTMPFile)
		tbsFile = approvalTMPFile.Name()
	}

	timeStampTMPFile, err := os.CreateTemp("", fmt.Sprintf("%s_timestamp_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(timeStampTMPFile.Name())
	}()

	err = sign.SignFile(tbsFile, timeStampTMPFile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: sign.TSA{
			URL: testpki.StartMockTSA(t),
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
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: sign.TSA{
			URL: testpki.StartMockTSA(t),
		},
	})
	if err != nil {
		t.Fatalf("%s: %s", "testfile20.pdf", err.Error())
	}

	verifySignedFile(t, tmpfile, "testfile20.pdf")
}

// TestSignPDFWithImage tests signing a PDF with an image in the signature
func TestSignPDFWithImage(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/images/pdfsign-signature.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile(inputFilePath, tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
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
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	tbsFile := "../testfiles/testfile12.pdf"

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/images/pdfsign-signature.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	// First signature
	firstSignature, err := os.CreateTemp("", fmt.Sprintf("%s_first_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(firstSignature.Name())
	}()

	err = sign.SignFile(tbsFile, firstSignature.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "First signature with image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
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

	verifyIntermediateFile(t, firstSignature)

	// Second signature
	secondSignature, err := os.CreateTemp("", fmt.Sprintf("%s_second_", t.Name()))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(secondSignature.Name())
	}()

	err = sign.SignFile(firstSignature.Name(), secondSignature.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "Jane Doe",
				Location:    "Elsewhere",
				Reason:      "Second signature with image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
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
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/images/pdfsign-signature-watermark.jpg")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile(inputFilePath, tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "James SuperSmith",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and watermark image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
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
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile12.pdf"
	originalFileName := filepath.Base(inputFilePath)

	// Read the signature image file
	signatureImage, err := os.ReadFile("../testfiles/images/pdfsign-signature-watermark.png")
	if err != nil {
		t.Fatalf("Failed to read signature image: %s", err.Error())
	}

	tmpfile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() {
		_ = os.Remove(tmpfile.Name())
	}()

	err = sign.SignFile(inputFilePath, tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "James SuperSmith",
				Location:    "Somewhere",
				Reason:      "Test with visible signature and watermark image",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
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
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
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
		_ = os.Remove(tmpfile.Name())
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
	err = sign.Sign(input_file, tmpfile, rdr, size, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere on the globe",
				Reason:      "My season for signing this document",
				ContactInfo: "How you like",
				Date:        time.Now().Local(),
			},
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:          pkey,          // crypto.Signer
		Certificate:     cert,          // x509.Certificate
		DigestAlgorithm: crypto.SHA256, // hash algorithm for the digest creation
		Appearance: sign.Appearance{ // Appearance is used for visual signatures
			Visible:          true,
			Page:             uint32(lastPage),
			LowerLeftX:       10,
			LowerLeftY:       10,
			UpperRightX:      200,
			UpperRightY:      100,
			ImageAsWatermark: true,
		},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifySignedFile(t, tmpfile, originalFileName)
}

func TestSignPDF_AppendToMultiSig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	cert, pkey := sign.LoadCertificateAndKey(t)

	fName := "testfile_multi.pdf"
	inputPath := filepath.Join("../testfiles", fName)
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		t.Skipf("%s not found", fName)
	}

	// This test appends a signature to a file that already contains signatures.
	// We specifically test that we can successfully add a valid SHA-512 signature
	// even if the existing signatures use older algorithms (like SHA-1) that might
	// fail our strict verification checks.
	outputName := fmt.Sprintf("testfile_multi_Append_%s.pdf", time.Now().Format("20060102150405"))
	var outputFile *os.File
	var err error
	if testing.Verbose() {
		outputFile, err = os.Create(filepath.Join("../testfiles/success", outputName))
	} else {
		outputFile, err = os.CreateTemp("", "test_multi_append")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = outputFile.Close()
		if !testing.Verbose() {
			_ = os.Remove(outputFile.Name())
		}
	}()

	err = sign.SignFile(inputPath, outputFile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
		},
		Signer:             pkey,
		Certificate:        cert,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
		DigestAlgorithm:    crypto.SHA512,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Manual Verification looking for valid LAST signature
	f, err := os.Open(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	doc, err := pdfsign.Open(f, info.Size())
	if err != nil {
		t.Fatal(err)
	}

	// TrustSelfSigned(true) is required for test certificates
	vRes := doc.Verify().TrustSelfSigned(true)

	// We expect verification might fail overall due to existing SHA-1 signatures
	// matching our strict criteria, but we verify that *our* new signature is valid.
	signatures := vRes.Signatures()
	if len(signatures) == 0 {
		t.Fatal("No signatures found")
	}

	lastSig := signatures[len(signatures)-1]
	if !lastSig.Valid {
		t.Errorf("Last signature should be valid, but got errors: %v", lastSig.Errors)
	}
}

// oidSigningCertificateV2 is the ESS signing-certificate-v2 signed attribute.
var oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

// oidSignatureTimeStampToken is the RFC 3161 signature-time-stamp attribute.
var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// signIncremental signs inputFilePath and returns the signed file together
// with only the appended incremental update, so that profile assertions are
// not defeated by signatures already present in the input.
func signIncremental(t *testing.T, inputFilePath string, signData sign.SignData) (*os.File, []byte) {
	t.Helper()

	originalContent, err := os.ReadFile(inputFilePath)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	tmpfile, err := os.CreateTemp(t.TempDir(), strings.ReplaceAll(t.Name(), "/", "_"))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	if err := sign.SignFile(inputFilePath, tmpfile.Name(), signData); err != nil {
		t.Fatalf("%s", err.Error())
	}

	signedFileContent, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if len(signedFileContent) <= len(originalContent) || !bytes.HasPrefix(signedFileContent, originalContent) {
		t.Fatal("signed file is not an incremental update of the input")
	}

	return tmpfile, signedFileContent[len(originalContent):]
}

// parseSignatureCMS extracts the CMS SignedData from the /Contents entry.
func parseSignatureCMS(t *testing.T, incrementalUpdate []byte) *pkcs7.PKCS7 {
	t.Helper()

	contentsMatch := regexp.MustCompile(`/Contents<([0-9a-fA-F]+)>`).FindSubmatch(incrementalUpdate)
	if contentsMatch == nil {
		t.Fatal("no /Contents entry found in signed file")
	}
	cms, err := hex.DecodeString(string(contentsMatch[1]))
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	p7, err := pkcs7.Parse(cms)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	return p7
}

// assertPAdESBaseline checks the ETSI EN 319 142-1 requirements common to all levels.
func assertPAdESBaseline(t *testing.T, incrementalUpdate []byte) *pkcs7.PKCS7 {
	t.Helper()

	if !bytes.Contains(incrementalUpdate, []byte("/SubFilter /ETSI.CAdES.detached")) {
		t.Fatal("signature dictionary does not use SubFilter ETSI.CAdES.detached")
	}
	if bytes.Contains(incrementalUpdate, []byte("/SubFilter /adbe.pkcs7.detached")) {
		t.Fatal("signature dictionary still uses SubFilter adbe.pkcs7.detached")
	}
	if !bytes.Contains(incrementalUpdate, []byte(" /M ")) {
		t.Fatal("signature dictionary does not contain the /M signing time entry")
	}
	if bytes.Contains(incrementalUpdate, []byte(" /Cert ")) {
		t.Error("signature dictionary contains a /Cert entry, which PAdES does not allow")
	}

	p7 := parseSignatureCMS(t, incrementalUpdate)

	if len(p7.Signers) != 1 {
		t.Fatalf("CMS contains %d signers, PAdES allows exactly one", len(p7.Signers))
	}

	var hasMessageDigest, hasSigningCertificate bool
	for _, attribute := range p7.Signers[0].AuthenticatedAttributes {
		switch {
		case attribute.Type.Equal(pkcs7.OIDAttributeSigningTime):
			t.Error("CMS contains the signing-time signed attribute, which is not allowed in PAdES baseline signatures")
		case attribute.Type.Equal(pkcs7.OIDAttributeMessageDigest):
			hasMessageDigest = true
		case attribute.Type.Equal(oidSigningCertificateV2):
			hasSigningCertificate = true
		}
	}

	if !hasMessageDigest {
		t.Error("CMS does not contain the message-digest signed attribute")
	}
	if !hasSigningCertificate {
		t.Error("CMS does not contain the signing-certificate-v2 signed attribute")
	}

	var contentType asn1.ObjectIdentifier
	if err := p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType); err != nil {
		t.Errorf("failed to read the content-type signed attribute: %s", err.Error())
	} else if !contentType.Equal(pkcs7.OIDData) {
		t.Errorf("content-type attribute is %v, want id-data", contentType)
	}

	return p7
}

func TestSignPDFPAdESBaseline(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, incrementalUpdate := signIncremental(t, inputFilePath, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name: "John Doe",
				Date: time.Now().Local(),
			},
			CertType: sign.ApprovalSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		SubFilter:       sign.SubFilterETSICAdESDetached,
	})

	assertPAdESBaseline(t, incrementalUpdate)

	verifySignedFile(t, tmpfile, filepath.Base(inputFilePath))
}

// TestSignPDFPAdESBaselineWithTimestamp: a signature-time-stamp does not
// remove the /M requirement.
func TestSignPDFPAdESBaselineWithTimestamp(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, incrementalUpdate := signIncremental(t, inputFilePath, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name: "John Doe",
				Date: time.Now().Local(),
			},
			CertType: sign.ApprovalSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		SubFilter:       sign.SubFilterETSICAdESDetached,
		TSA: sign.TSA{
			URL: testpki.StartMockTSA(t),
		},
	})

	p7 := assertPAdESBaseline(t, incrementalUpdate)

	var timeStampToken *timestamp.Timestamp
	for _, attribute := range p7.Signers[0].UnauthenticatedAttributes {
		if attribute.Type.Equal(oidSignatureTimeStampToken) {
			var err error
			timeStampToken, err = timestamp.Parse(attribute.Value.Bytes)
			if err != nil {
				t.Fatalf("failed to parse the signature-time-stamp attribute: %s", err.Error())
			}
		}
	}
	if timeStampToken == nil {
		t.Fatal("CMS does not contain the signature-time-stamp unsigned attribute")
	}

	// The messageImprint shall hash the signature value (ETSI EN 319 122-1).
	imprint := timeStampToken.HashAlgorithm.New()
	imprint.Write(p7.Signers[0].EncryptedDigest)
	if !bytes.Equal(timeStampToken.HashedMessage, imprint.Sum(nil)) {
		t.Error("signature-time-stamp message imprint does not cover the CMS signature value")
	}

	verifySignedFile(t, tmpfile, filepath.Base(inputFilePath))
}

func TestSignPDFPAdESRejectsWeakDigest(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}

	for _, digest := range []crypto.Hash{crypto.MD5, crypto.SHA1} {
		t.Run(digest.String(), func(t *testing.T) {
			tmpfile, err := os.CreateTemp(t.TempDir(), "weakdigest")
			if err != nil {
				t.Fatalf("%s", err.Error())
			}

			err = sign.SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), sign.SignData{
				Signature: sign.SignDataSignature{
					Info: sign.SignDataSignatureInfo{
						Name: "John Doe",
						Date: time.Now().Local(),
					},
					CertType: sign.ApprovalSignature,
				},
				DigestAlgorithm: digest,
				Signer:          pkey,
				Certificate:     cert,
				SubFilter:       sign.SubFilterETSICAdESDetached,
			})
			if err == nil {
				t.Fatalf("signing with %s succeeded, want an error for PAdES baseline signatures", digest)
			}
			if !strings.Contains(err.Error(), "digest algorithm") {
				t.Fatalf("got error %q, want the digest algorithm rejection", err.Error())
			}
		})
	}
}

// TestSignPDFPAdESDefaultSigningDate: /M shall be present even when the
// caller provides no signing date.
func TestSignPDFPAdESDefaultSigningDate(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, incrementalUpdate := signIncremental(t, inputFilePath, sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		SubFilter:       sign.SubFilterETSICAdESDetached,
	})

	assertPAdESBaseline(t, incrementalUpdate)

	verifySignedFile(t, tmpfile, filepath.Base(inputFilePath))
}

// TestSignPDFLegacyProfile pins the default profile: adbe.pkcs7.detached,
// CMS signing-time present, and no /M when a timestamp is embedded.
func TestSignPDFLegacyProfile(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile20.pdf"

	tmpfile, incrementalUpdate := signIncremental(t, inputFilePath, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name: "John Doe",
				Date: time.Now().Local(),
			},
			CertType: sign.ApprovalSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		TSA: sign.TSA{
			URL: testpki.StartMockTSA(t),
		},
	})

	if !bytes.Contains(incrementalUpdate, []byte("/SubFilter /adbe.pkcs7.detached")) {
		t.Fatal("legacy signature does not use SubFilter adbe.pkcs7.detached")
	}
	if bytes.Contains(incrementalUpdate, []byte("/SubFilter /ETSI.CAdES.detached")) {
		t.Fatal("legacy signature uses SubFilter ETSI.CAdES.detached")
	}
	if bytes.Contains(incrementalUpdate, []byte(" /M ")) {
		t.Error("legacy signature should omit the /M entry when an embedded timestamp is present")
	}

	p7 := parseSignatureCMS(t, incrementalUpdate)

	var hasSigningTime bool
	for _, attribute := range p7.Signers[0].AuthenticatedAttributes {
		if attribute.Type.Equal(pkcs7.OIDAttributeSigningTime) {
			hasSigningTime = true
		}
	}
	if !hasSigningTime {
		t.Error("legacy signature does not contain the signing-time signed attribute")
	}

	verifySignedFile(t, tmpfile, filepath.Base(inputFilePath))
}

// signingCertificateV2 mirrors RFC 5035 far enough to inspect ESSCertIDv2.
type signingCertificateV2 struct {
	Certs []essCertIDv2
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

// TestSignPDFPAdESSigningCertificateV2: the ESSCertIDv2 hash algorithm shall
// be absent for the DEFAULT SHA-256 (DER, X.690, 11.5) and explicit otherwise.
func TestSignPDFPAdESSigningCertificateV2(t *testing.T) {
	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}
	inputFilePath := "../testfiles/testfile20.pdf"

	for _, tc := range []struct {
		digest            crypto.Hash
		explicitAlgorithm asn1.ObjectIdentifier // nil when the DEFAULT applies
	}{
		{digest: crypto.SHA256},
		{digest: crypto.SHA512, explicitAlgorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
	} {
		t.Run(tc.digest.String(), func(t *testing.T) {
			_, incrementalUpdate := signIncremental(t, inputFilePath, sign.SignData{
				Signature: sign.SignDataSignature{
					Info: sign.SignDataSignatureInfo{
						Name: "John Doe",
						Date: time.Now().Local(),
					},
					CertType: sign.ApprovalSignature,
				},
				DigestAlgorithm: tc.digest,
				Signer:          pkey,
				Certificate:     cert,
				SubFilter:       sign.SubFilterETSICAdESDetached,
			})

			p7 := parseSignatureCMS(t, incrementalUpdate)

			var sc signingCertificateV2
			if err := p7.UnmarshalSignedAttribute(oidSigningCertificateV2, &sc); err != nil {
				t.Fatalf("failed to parse the signing-certificate-v2 attribute: %s", err.Error())
			}
			if len(sc.Certs) != 1 {
				t.Fatalf("signing-certificate-v2 contains %d certificate ids, want 1", len(sc.Certs))
			}
			id := sc.Certs[0]

			if tc.explicitAlgorithm == nil {
				if id.HashAlgorithm.Algorithm != nil {
					t.Errorf("ESSCertIDv2 encodes hash algorithm %v, but DER requires the DEFAULT id-sha256 to be absent", id.HashAlgorithm.Algorithm)
				}
			} else if !id.HashAlgorithm.Algorithm.Equal(tc.explicitAlgorithm) {
				t.Errorf("ESSCertIDv2 hash algorithm is %v, want %v", id.HashAlgorithm.Algorithm, tc.explicitAlgorithm)
			}

			hash := tc.digest.New()
			hash.Write(cert.Raw)
			if !bytes.Equal(id.CertHash, hash.Sum(nil)) {
				t.Error("ESSCertIDv2 certificate hash does not match the signing certificate")
			}
		})
	}
}
