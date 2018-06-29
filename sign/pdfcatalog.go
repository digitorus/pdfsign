package sign

import (
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

	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	if found_pages {
		pages := root.Key("Pages").GetPtr()
		catalog += " /Pages " + strconv.Itoa(int(pages.GetID())) + " " + strconv.Itoa(int(pages.GetGen())) + " R"
	}

	catalog += " /AcroForm <<"
	catalog += " /Fields [" + strconv.Itoa(int(context.VisualSignData.ObjectId)) + " 0 R]"

	switch context.SignData.Signature.CertType {
	case CertificationSignature, UsageRightsSignature:
		catalog += " /NeedAppearances false"
	}

	switch context.SignData.Signature.CertType {
	case CertificationSignature:
		catalog += " /SigFlags 3"
	case UsageRightsSignature:
		catalog += " /SigFlags 1"
	}

	catalog += " >>"

	switch context.SignData.Signature.CertType {
	case CertificationSignature:
		catalog += " /Perms << /DocMDP " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R >>"
	case UsageRightsSignature:
		catalog += " /Perms << /UR3 " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R >>"
	}

	catalog += " >>"
	catalog += "\nendobj\n"

	return catalog, nil
}
