package sign

import (
	"bytes"
	"fmt"
	"github.com/digitorus/pdf"
	"io"
	"slices"
	"strconv"
)

func (context *SignContext) createCatalog() ([]byte, error) {
	var overwrittenCatalogKeys []string
	var catalog_buffer bytes.Buffer

	// Start the catalog object
	catalog_buffer.WriteString("<<\n")
	catalog_buffer.WriteString("  /Type /Catalog\n")
	overwrittenCatalogKeys = append(overwrittenCatalogKeys, "Type")

	// (Optional; PDF 1.4) The version of the PDF specification to which
	// the document conforms (for example, 1.4) if later than the version
	// specified in the file’s header (see 7.5.2, "File header"). If the header
	// specifies a later version, or if this entry is absent, the document
	// shall conform to the version specified in the header. This entry
	// enables a PDF processor to update the version using an incremental
	// update; see 7.5.6, "Incremental updates".
	// The value of this entry shall be a name object, not a number, and
	// therefore shall be preceded by a SOLIDUS (2Fh) character (/) when
	// written in the PDF file (for example, /1.4).
	//
	// If an incremental upgrade requires a version that is higher than specified by the document.
	// if context.PDFReader.PDFVersion < "2.0" {
	// catalog_buffer.WriteString(" /Version /2.0")
	// }

	// Retrieve the root and check for necessary keys in one loop
	root := context.PDFReader.Trailer().Key("Root")
	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	foundPages, foundNames := false, false
	for _, key := range root.Keys() {
		switch key {
		case "Pages":
			foundPages = true
		case "Names":
			foundNames = true
		}
		if foundPages && foundNames {
			break
		}
	}

	// Add Pages and Names references if they exist
	if foundPages {
		pages := root.Key("Pages").GetPtr()
		catalog_buffer.WriteString("  /Pages " + strconv.Itoa(int(pages.GetID())) + " " + strconv.Itoa(int(pages.GetGen())) + " R\n")
		overwrittenCatalogKeys = append(overwrittenCatalogKeys, "Pages")
	}
	if foundNames {
		names := root.Key("Names").GetPtr()
		catalog_buffer.WriteString("  /Names " + strconv.Itoa(int(names.GetID())) + " " + strconv.Itoa(int(names.GetGen())) + " R\n")
		overwrittenCatalogKeys = append(overwrittenCatalogKeys, "Names")
	}

	// Start the AcroForm dictionary with /NeedAppearances
	overwrittenCatalogKeys = append(overwrittenCatalogKeys, "AcroForm")
	catalog_buffer.WriteString("  /AcroForm <<\n")
	catalog_buffer.WriteString("    /Fields [")

	// Add existing signatures to the AcroForm dictionary
	for i, sig := range context.existingSignatures {
		if i > 0 {
			catalog_buffer.WriteString(" ")
		}
		catalog_buffer.WriteString(strconv.Itoa(int(sig.objectId)) + " 0 R")
	}

	// Add the visual signature field to the AcroForm dictionary
	if len(context.existingSignatures) > 0 {
		catalog_buffer.WriteString(" ")
	}
	catalog_buffer.WriteString(strconv.Itoa(int(context.VisualSignData.objectId)) + " 0 R")

	catalog_buffer.WriteString("]\n") // close Fields array

	// (Optional; deprecated in PDF 2.0) A flag specifying whether
	// to construct appearance streams and appearance
	// dictionaries for all widget annotations in the document (see
	// 12.7.4.3, "Variable text"). Default value: false. A PDF writer
	// shall include this key, with a value of true, if it has not
	// provided appearance streams for all visible widget
	// annotations present in the document.
	// if context.SignData.Visible {
	// 	catalog_buffer.WriteString(" /NeedAppearances true")
	// } else {
	// 	catalog_buffer.WriteString(" /NeedAppearances false")
	// }

	// Signature flags (Table 225)
	//
	// Bit position 1: SignaturesExist
	// If set, the document contains at least one signature field. This
	// flag allows an interactive PDF processor to enable user
	// interface items (such as menu items or push-buttons) related to
	// signature processing without having to scan the entire
	// document for the presence of signature fields.
	//
	// Bit position 2: AppendOnly
	// If set, the document contains signatures that may be invalidated
	// if the PDF file is saved (written) in a way that alters its previous
	// contents, as opposed to an incremental update. Merely updating
	// the PDF file by appending new information to the end of the
	// previous version is safe (see H.7, "Updating example").
	// Interactive PDF processors may use this flag to inform a user
	// requesting a full save that signatures will be invalidated and
	// require explicit confirmation before continuing with the
	// operation.
	//
	// Set SigFlags and Permissions based on Signature Type
	switch context.SignData.Signature.CertType {
	case CertificationSignature, ApprovalSignature, TimeStampSignature:
		catalog_buffer.WriteString("    /SigFlags 3\n")
	case UsageRightsSignature:
		catalog_buffer.WriteString("    /SigFlags 1\n")
	}

	// Finalize the AcroForm and Catalog object
	catalog_buffer.WriteString("  >>\n") // Close AcroForm

	// Copy over existing catalog entries from the original document that we did not need to override.
	for _, key := range root.Keys() {
		if !slices.Contains(overwrittenCatalogKeys, key) {
			_, _ = fmt.Fprintf(&catalog_buffer, "/%s ", key)
			context.serializeCatalogEntry(&catalog_buffer, rootPtr.GetID(), root.Key(key))
		}
	}
	catalog_buffer.WriteString(">>\n") // Close Catalog

	return catalog_buffer.Bytes(), nil
}

// serializeCatalogEntry takes a pdf.Value and serializes it to the given writer.
func (context *SignContext) serializeCatalogEntry(w io.Writer, rootObjId uint32, value pdf.Value) {
	if ptr := value.GetPtr(); ptr.GetID() != rootObjId {
		// Indirect object
		_, _ = fmt.Fprintf(w, "%d %d R", ptr.GetID(), ptr.GetGen())
		return
	}

	// Direct object
	switch value.Kind() {
	case pdf.String:
		_, _ = fmt.Fprintf(w, "(%s)", value.RawString())
	case pdf.Null:
		_, _ = fmt.Fprint(w, "null")
	case pdf.Bool:
		if value.Bool() {
			_, _ = fmt.Fprint(w, "true")
		} else {
			_, _ = fmt.Fprint(w, "false")
		}
	case pdf.Integer:
		_, _ = fmt.Fprintf(w, "%d", value.Int64())
	case pdf.Real:
		_, _ = fmt.Fprintf(w, "%f", value.Float64())
	case pdf.Name:
		_, _ = fmt.Fprintf(w, "/%s", value.Name())
	case pdf.Dict:
		_, _ = fmt.Fprint(w, "<<")
		for idx, key := range value.Keys() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			_, _ = fmt.Fprintf(w, "/%s ", key)
			context.serializeCatalogEntry(w, rootObjId, value.Key(key))
		}
		_, _ = fmt.Fprint(w, ">>")
	case pdf.Array:
		_, _ = fmt.Fprint(w, "[")
		for idx := range value.Len() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			context.serializeCatalogEntry(w, rootObjId, value.Index(idx))
		}
		_, _ = fmt.Fprint(w, "]")
	case pdf.Stream:
		panic("stream cannot be a direct object")
	}
}
