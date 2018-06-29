package sign

import (
	"os"
	"testing"
	"time"

	"bitbucket.org/digitorus/pdf"
)

func TestCreateSignature(t *testing.T) {
	input_file, err := os.Open("../testfiles/testfile20.pdf")
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	finfo, err := input_file.Stat()
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	timezone, _ := time.LoadLocation("Europe/Tallinn")
	now := time.Date(2017, 9, 23, 14, 39, 0, 0, timezone)

	sign_data := SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "Jeroen Bobbeldijk",
				Location:    "Rotterdam",
				Reason:      "Test",
				ContactInfo: "Geen",
				Date:        now,
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
	}

	sign_data.ObjectId = uint32(rdr.XrefInformation.ItemCount) + 3

	context := SignContext{
		Filesize:  size + 1,
		PDFReader: rdr,
		InputFile: input_file,
		VisualSignData: VisualSignData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount),
		},
		CatalogData: CatalogData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount) + 1,
		},
		InfoData: InfoData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount) + 2,
		},
		SignData: sign_data,
	}

	expected_signature := "13 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange[0 ********** ********** **********] /Contents<> /Reference [ << /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >> ] /Name (Jeroen Bobbeldijk) /Location (Rotterdam) /Reason (Test) /ContactInfo (Geen) /M (D:20170923143900+03'00') >>\nendobj\n"

	signature, byte_range_start_byte, signature_contents_start_byte := context.createSignaturePlaceholder()

	if signature != expected_signature {
		t.Errorf("Signature mismatch, expected %s, but got %s", expected_signature, signature)
	}

	if byte_range_start_byte != 78 {
		t.Errorf("Byte range start mismatch, expected %d, but got %d", 78, byte_range_start_byte)
	}

	if signature_contents_start_byte != 135 {
		t.Errorf("Signature contents start byte mismatch, expected %d, but got %d", 135, signature_contents_start_byte)
	}
}
