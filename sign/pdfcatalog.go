package sign

import (
	"errors"
	"strconv"
)

func (context *SignContext) createCatalog() (catalog string, err error) {
	catalog = strconv.Itoa(int(context.CatalogData.ObjectId)) + " 0 obj\n"
	catalog += "<< /Type /Catalog"
	catalog += " /Version /" + context.PDFReader.PDFVersion

	root := context.PDFReader.Trailer().Key("Root")
	root_keys := root.Keys()
	found_pages := false
	for _, key := range root_keys {
		if key == "Pages" {
			found_pages = true
			break
		}
	}

	if !found_pages {
		return "", errors.New("Didn't find pages in PDF trailer Root.")
	}

	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	pages := root.Key("Pages").GetPtr()
	catalog += " /Pages " + strconv.Itoa(int(pages.GetID())) + " " + strconv.Itoa(int(pages.GetGen())) + " R"
	catalog += " /AcroForm <<"
	catalog += " /Fields [" + strconv.Itoa(int(context.VisualSignData.ObjectId)) + " 0 R]"

	if !context.SignData.Signature.Approval {
		catalog += " /NeedAppearances false"
	}

	if context.SignData.Signature.CertType > 0 {
		catalog += " /SigFlags 3"
	} else {
		catalog += " /SigFlags 1"
	}

	catalog += " >>"

	if !context.SignData.Signature.Approval {
		if context.SignData.Signature.CertType > 0 {
			catalog += " /Perms << /DocMDP " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R >>";
		} else {
			catalog += " /Perms << /UR3 " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R >>";
		}
	}

	catalog += " >>"
	catalog += "\nendobj\n"

	return catalog, nil
}
