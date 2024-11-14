package sign

import (
	"fmt"
	"os"
	"testing"

	"github.com/digitorus/pdf"
)

var testFiles = []struct {
	file             string
	expectedCatalogs map[CertType]string
}{
	{
		file: "../testfiles/testfile20.pdf",
		expectedCatalogs: map[CertType]string{
			CertificationSignature: "11 0 obj\n<< /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 3 >> >>\nendobj\n",
			UsageRightsSignature:   "11 0 obj\n<< /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 1 >> >>\nendobj\n",
			ApprovalSignature:      "11 0 obj\n<< /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 3 >> >>\nendobj\n",
		},
	},
	{
		file: "../testfiles/testfile21.pdf",
		expectedCatalogs: map[CertType]string{
			CertificationSignature: "17 0 obj\n<< /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 3 >> >>\nendobj\n",
			UsageRightsSignature:   "17 0 obj\n<< /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 1 >> >>\nendobj\n",
			ApprovalSignature:      "17 0 obj\n<< /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 3 >> >>\nendobj\n",
		},
	},
}

func TestCreateCatalog(t *testing.T) {
	for _, testFile := range testFiles {
		for certType, expectedCatalog := range testFile.expectedCatalogs {
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

				context := SignContext{
					Filesize:  size + 1,
					PDFReader: rdr,
					InputFile: inputFile,
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
							CertType:   certType,
							DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
						},
					},
				}

				catalog, err := context.createCatalog()
				if err != nil {
					st.Errorf("%s", err.Error())
					return
				}

				if catalog != expectedCatalog {
					st.Errorf("Catalog mismatch, expected %s, but got %s", expectedCatalog, catalog)
				}
			})
		}
	}
}
