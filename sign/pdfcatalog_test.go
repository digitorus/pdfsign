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
			CertificationSignature: "<<\n  /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 3 >>\n>>\n",
			UsageRightsSignature:   "<<\n  /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 1 >>\n>>\n",
			ApprovalSignature:      "<<\n  /Type /Catalog /Pages 3 0 R /AcroForm << /Fields [10 0 R] /NeedAppearances false /SigFlags 3 >>\n>>\n",
		},
	},
	{
		file: "../testfiles/testfile21.pdf",
		expectedCatalogs: map[CertType]string{
			CertificationSignature: "<<\n  /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 3 >>\n>>\n",
			UsageRightsSignature:   "<<\n  /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 1 >>\n>>\n",
			ApprovalSignature:      "<<\n  /Type /Catalog /Pages 9 0 R /Names 6 0 R /AcroForm << /Fields [16 0 R] /NeedAppearances false /SigFlags 3 >>\n>>\n",
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

				if string(catalog) != expectedCatalog {
					st.Errorf("Catalog mismatch, expected\n%s\nbut got\n%s", expectedCatalog, catalog)
				}
			})
		}
	}
}
