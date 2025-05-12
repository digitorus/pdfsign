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
			CertificationSignature: "<<\n  /Type /Catalog\n  /Metadata 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [10 0 R]\n    /SigFlags 3\n  >>\n>>\n",
			UsageRightsSignature:   "<<\n  /Type /Catalog\n  /Metadata 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [10 0 R]\n    /SigFlags 1\n  >>\n>>\n",
			ApprovalSignature:      "<<\n  /Type /Catalog\n  /Metadata 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [10 0 R]\n    /SigFlags 3\n  >>\n>>\n",
		},
	},
	{
		file: "../testfiles/testfile12.pdf",
		expectedCatalogs: map[CertType]string{
			CertificationSignature: "<<\n  /Type /Catalog\n  /Version /1.5\n  /Outlines 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [16 0 R]\n    /SigFlags 3\n  >>\n>>\n",
			UsageRightsSignature:   "<<\n  /Type /Catalog\n  /Version /1.5\n  /Outlines 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [16 0 R]\n    /SigFlags 1\n  >>\n>>\n",
			ApprovalSignature:      "<<\n  /Type /Catalog\n  /Version /1.5\n  /Outlines 2 0 R\n  /Pages 3 0 R\n  /AcroForm <<\n    /Fields [16 0 R]\n    /SigFlags 3\n  >>\n>>\n",
		},
	},
}

func TestCreateCatalog(t *testing.T) {
	for _, testFile := range testFiles {
		for certType, expectedCatalog := range testFile.expectedCatalogs {
			t.Run(fmt.Sprintf("%s_%s", testFile.file, certType.String()), func(st *testing.T) {
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
						objectId: uint32(rdr.XrefInformation.ItemCount),
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
					st.Errorf("Catalog mismatch, expected\n%q\nbut got\n%q", expectedCatalog, catalog)
				}
			})
		}
	}
}
