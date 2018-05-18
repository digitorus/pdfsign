package sign

import (
	"os"
	"testing"

	"bitbucket.org/digitorus/pdf"
	"time"
)

func TestCreateInfoEmpty(t *testing.T) {
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

	sign_data := SignData{
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

	info, err := context.createInfo()
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	expected_info := "12 0 obj\n<<>>\nendobj\n"
	if info != expected_info {
		t.Errorf("Info mismatch, expected %s, but got %s", expected_info, info)
	}
}

func TestCreateInfo(t *testing.T) {
	input_file, err := os.Open("../testfiles/testfile12.pdf")
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

	sign_data := SignData{
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

	info, err := context.createInfo()
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	expected_info := "18 0 obj\n<</Author(User: Isamu Ohzawa [isamu])/CreationDate(D:19981025161109)/Creator(FastIO Systems: cover.c)/Keywords(ClibPDF, ANSI C Library, Acrobat, PDF, Dynamic Web, Graph, Plot)/Producer([ClibPDF Library 0.96] NEXTSTEP or OPENSTEP)/Subject(ANSI C Library for Direct PDF Generation)/Title(ClibPDF Reference Manual)>>\nendobj\n"

	if info != expected_info {
		t.Errorf("Info mismatch, expected %s, but got %s", expected_info, info)
	}
}
