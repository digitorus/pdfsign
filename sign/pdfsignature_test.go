package sign

// import (
// 	"fmt"
// 	"os"
// 	"testing"
// 	"time"

// 	"github.com/digitorus/pdf"
// )

// var signatureTests = []struct {
// 	file               string
// 	expectedSignatures map[uint]string
// }{
// 	{
// 		file: "../testfiles/testfile20.pdf",
// 		expectedSignatures: map[uint]string{
// 			CertificationSignature: "13 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange[0 ********** ********** **********] /Contents<> /Reference [ << /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >> ] /Name (John Doe) /Location (Somewhere) /Reason (Test) /ContactInfo (None) /M (D:20170923143900+03'00') >>\nendobj\n",
// 			UsageRightsSignature:   "13 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange[0 ********** ********** **********] /Contents<> /Reference [ << /Type /SigRef /TransformMethod /UR3 /TransformParams << /Type /TransformParams /V /2.2 >> >> ] /Name (John Doe) /Location (Somewhere) /Reason (Test) /ContactInfo (None) /M (D:20170923143900+03'00') >>\nendobj\n",
// 			ApprovalSignature:      "13 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange[0 ********** ********** **********] /Contents<> /Reference [ << /Type /SigRef /TransformMethod /FieldMDP /TransformParams << /Type /TransformParams /Fields [<< /Type /SigFieldLock /Action /All >>] /V /1.2 >> >> ] /Name (John Doe) /Location (Somewhere) /Reason (Test) /ContactInfo (None) /M (D:20170923143900+03'00') >>\nendobj\n",
// 		},
// 	},
// }

// func TestCreateSignaturePlaceholder(t *testing.T) {
// 	for _, testFile := range signatureTests {
// 		for certType, expectedSignature := range testFile.expectedSignatures {
// 			t.Run(fmt.Sprintf("%s_certType-%d", testFile.file, certType), func(st *testing.T) {
// 				inputFile, err := os.Open(testFile.file)
// 				if err != nil {
// 					st.Errorf("Failed to load test PDF")
// 					return
// 				}

// 				finfo, err := inputFile.Stat()
// 				if err != nil {
// 					st.Errorf("Failed to load test PDF")
// 					return
// 				}
// 				size := finfo.Size()

// 				rdr, err := pdf.NewReader(inputFile, size)
// 				if err != nil {
// 					st.Errorf("Failed to load test PDF")
// 					return
// 				}

// 				timezone, _ := time.LoadLocation("Europe/Tallinn")
// 				now := time.Date(2017, 9, 23, 14, 39, 0, 0, timezone)

// 				sign_data := SignData{
// 					Signature: SignDataSignature{
// 						Info: SignDataSignatureInfo{
// 							Name:        "John Doe",
// 							Location:    "Somewhere",
// 							Reason:      "Test",
// 							ContactInfo: "None",
// 							Date:        now,
// 						},
// 						CertType:   certType,
// 						DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
// 					},
// 				}

// 				sign_data.ObjectId = uint32(rdr.XrefInformation.ItemCount) + 3

// 				context := SignContext{
// 					Filesize:  size + 1,
// 					PDFReader: rdr,
// 					InputFile: inputFile,
// 					VisualSignData: VisualSignData{
// 						ObjectId: uint32(rdr.XrefInformation.ItemCount),
// 					},
// 					CatalogData: CatalogData{
// 						ObjectId: uint32(rdr.XrefInformation.ItemCount) + 1,
// 					},
// 					InfoData: InfoData{
// 						ObjectId: uint32(rdr.XrefInformation.ItemCount) + 2,
// 					},
// 					SignData: sign_data,
// 				}

// 				signature, byte_range_start_byte, signature_contents_start_byte := context.createSignaturePlaceholder()

// 				if signature != expectedSignature {
// 					st.Errorf("Signature mismatch, expected %s, but got %s", expectedSignature, signature)
// 				}

// 				if byte_range_start_byte != 78 {
// 					st.Errorf("Byte range start mismatch, expected %d, but got %d", 78, byte_range_start_byte)
// 				}

// 				if signature_contents_start_byte != 135 {
// 					st.Errorf("Signature contents start byte mismatch, expected %d, but got %d", 135, signature_contents_start_byte)
// 				}
// 			})
// 		}
// 	}
// }
