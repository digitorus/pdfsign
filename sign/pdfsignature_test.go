package sign

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdf"
)

var signatureTests = []struct {
	file               string
	expectedSignatures map[CertType]string
}{
	{
		file: "../testfiles/testfile20.pdf",
		expectedSignatures: map[CertType]string{
			CertificationSignature: "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /adbe.pkcs7.detached\n /Prop_Build <<\n   /App << /Name /Digitorus#20PDFSign >>\n >>\n /ByteRange[0 ********** ********** **********] /Contents<>\n /Reference [\n << /Type /SigRef\n /TransformMethod /DocMDP\n /TransformParams <<\n   /Type /TransformParams\n   /P 2   /V /1.2\n   >>\n >> ] /Name (John Doe)\n /Location (Somewhere)\n /Reason (Test)\n /ContactInfo (None)\n /M (D:20170923143900+03'00')\n>>\n",
			UsageRightsSignature:   "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /adbe.pkcs7.detached\n /Prop_Build <<\n   /App << /Name /Digitorus#20PDFSign >>\n >>\n /ByteRange[0 ********** ********** **********] /Contents<>\n /Reference [\n << /Type /SigRef\n   /TransformMethod /UR3\n   /TransformParams <<\n     /Type /TransformParams\n     /V /2.2\n   >>\n >> ] /Name (John Doe)\n /Location (Somewhere)\n /Reason (Test)\n /ContactInfo (None)\n /M (D:20170923143900+03'00')\n>>\n",
			ApprovalSignature:      "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /adbe.pkcs7.detached\n /Prop_Build <<\n   /App << /Name /Digitorus#20PDFSign >>\n >>\n /ByteRange[0 ********** ********** **********] /Contents<>\n   /TransformMethod /FieldMDP\n   /TransformParams <<\n     /Type /TransformParams\n     /Action /All\n     /V /1.2\n >>\n /Name (John Doe)\n /Location (Somewhere)\n /Reason (Test)\n /ContactInfo (None)\n /M (D:20170923143900+03'00')\n>>\n",
		},
	},
}

func TestCreateSignaturePlaceholder(t *testing.T) {
	for _, testFile := range signatureTests {
		for certType, expectedSignature := range testFile.expectedSignatures {
			t.Run(fmt.Sprintf("%s_certType-%d", testFile.file, certType), func(st *testing.T) {
				inputFile, err := os.Open(testFile.file)
				if err != nil {
					st.Errorf("Failed to load test PDF")
					return
				}

				finfo, err := inputFile.Stat()
				if err != nil {
					st.Errorf("Failed to load test PDF")
					return
				}
				size := finfo.Size()

				rdr, err := pdf.NewReader(inputFile, size)
				if err != nil {
					st.Errorf("Failed to load test PDF")
					return
				}

				timezone, _ := time.LoadLocation("Europe/Tallinn")
				now := time.Date(2017, 9, 23, 14, 39, 0, 0, timezone)

				sign_data := SignData{
					Signature: SignDataSignature{
						Info: SignDataSignatureInfo{
							Name:        "John Doe",
							Location:    "Somewhere",
							Reason:      "Test",
							ContactInfo: "None",
							Date:        now,
						},
						CertType:   certType,
						DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
					},
				}

				sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 3

				context := SignContext{
					PDFReader: rdr,
					InputFile: inputFile,
					SignData:  sign_data,
				}

				signature := context.createSignaturePlaceholder()

				if string(signature) != expectedSignature {
					st.Errorf("Signature mismatch, expected:\n%q\nbut got:\n%q", expectedSignature, signature)
				}
			})
		}
	}
}
