package sign

import (
	"strconv"
)

func (context *SignContext) createVisualSignature() (visual_signature string, err error) {
	visual_signature = strconv.Itoa(int(context.VisualSignData.ObjectId)) + " 0 obj\n"
	visual_signature += "<< /Type /Annot"
	visual_signature += " /Subtype /Widget"
	visual_signature += " /Rect [0 0 0 0]"

	root := context.PDFReader.Trailer().Key("Root")
	root_keys := root.Keys()
	found_pages := false
	for _, key := range root_keys {
		if key == "Pages" {
			found_pages = true
			break
		}
	}

	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	if found_pages {
		first_page, err := findFirstPage(root.Key("Pages"))
		if err != nil {
			return "", err
		}

		first_page_ptr := first_page.GetPtr()

		visual_signature += " /P " + strconv.Itoa(int(first_page_ptr.GetID())) + " " + strconv.Itoa(int(first_page_ptr.GetGen())) + " R"
	}

	visual_signature += " /F 132"
	visual_signature += " /FT /Sig"
	visual_signature += " /T " + pdfString("Signature")
	visual_signature += " /Ff 0"
	visual_signature += " /V " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R"

	visual_signature += " >>"
	visual_signature += "\nendobj\n"

	return visual_signature, nil
}
