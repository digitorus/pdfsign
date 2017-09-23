package sign

import (
	"os"
	"testing"

	"bitbucket.org/digitorus/pdf"
)

func TestCreateCatalog(t *testing.T) {
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
	}

	catalog, err := context.createCatalog()
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	expected_catalog := "11 0 obj\n<< /Type /Catalog /Version /2.0 /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 1 >> /Perms << /UR3 0 0 R >> >>\nendobj\n"

	if catalog != expected_catalog {
		t.Errorf("Catalog mismatch, expected %s, but got %s", expected_catalog, catalog)
	}
}
