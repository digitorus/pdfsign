package sign

import (
	"os"
	"testing"
	"time"

	"bitbucket.org/digitorus/pdf"
)

func TestVisualSignature(t *testing.T) {
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
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignatures,
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

	expected_visual_signature := "10 0 obj\n<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /P 4 0 R /F 132 /FT /Sig /T (Signature) /Ff 0 /V 13 0 R >>\nendobj\n"

	visual_signature, err := context.createVisualSignature()
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	if visual_signature != expected_visual_signature {
		t.Errorf("Visual signature mismatch, expected %s, but got %s", expected_visual_signature, visual_signature)
	}
}
