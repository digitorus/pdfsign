package sign

import (
	"os"
	"testing"

	"github.com/digitorus/pdf"
)

var test_files = []struct {
	file             string
	expected_catalog string
}{
	{"../testfiles/testfile20.pdf", "11 0 obj\n<< /Type /Catalog /Version /2.0 /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 1 >> /Perms << /UR3 0 0 R >> >>\nendobj\n"},
	{"../testfiles/testfile21.pdf", "17 0 obj\n<< /Type /Catalog /Version /1.0 /Names 6 0 R /Pages 9 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 1 >> /Perms << /UR3 0 0 R >> >>\nendobj\n"},
}

func TestCreateCatalog(t *testing.T) {
	for _, test_file := range test_files {
		input_file, err := os.Open(test_file.file)
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
			SignData: SignData{
				Signature: SignDataSignature{
					CertType:   UsageRightsSignature,
					DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
				},
			},
		}

		catalog, err := context.createCatalog()
		if err != nil {
			t.Errorf("%s", err.Error())
			return
		}

		if catalog != test_file.expected_catalog {
			t.Errorf("Catalog mismatch, expected %s, but got %s", test_file.expected_catalog, catalog)
		}
	}
}
