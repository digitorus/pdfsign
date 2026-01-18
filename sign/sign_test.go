package sign_test

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
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
				t.Errorf("Signature verification failed: %v", sig.Errors)
			}
		}
		t.Fatalf("%s: signature validation failed", tmpfile.Name())
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
			URL: "http://timestamp.digicert.com",
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
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
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
			if err := os.Remove(approvalTMPFile.Name()); err != nil {
				t.Errorf("Failed to remove approvalTMPFile: %v", err)
			}
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

		verifySignedFile(t, approvalTMPFile, filepath.Base(tbsFile))
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
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
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

	err = sign.SignFile(tbsFile, timeStampTMPFile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: sign.TSA{
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

	err = sign.SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA512,
		TSA: sign.TSA{
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
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
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
		if err := os.Remove(firstSignature.Name()); err != nil {
			t.Errorf("Failed to remove firstSignature: %v", err)
		}
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
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
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
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Errorf("Failed to remove tmpfile: %v", err)
		}
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
