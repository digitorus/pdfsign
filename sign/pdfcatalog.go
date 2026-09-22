package sign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/digitorus/pdf"
)

func (context *SignContext) createCatalog() ([]byte, error) {
	var catalog_buffer bytes.Buffer

	// Start the catalog object
	catalog_buffer.WriteString("<<\n")
	catalog_buffer.WriteString("  /Type /Catalog\n")

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
	// Ensure PDF version is at least 1.5 to support SigFlags in acroFormDict (1.4) and UF in the fileSpecDict (1.5)
	if v, err := strconv.ParseFloat(context.PDFReader.PDFVersion, 64); err == nil && v < 1.5 {
		catalog_buffer.WriteString("  /Version /1.5\n")
	}

	// Retrieve the root, its pointer and set the root string
	root := context.PDFReader.Trailer().Key("Root")
	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	// A certification signature has to be referenced from the catalog /Perms
	// dictionary (see writePermsWithDocMDP below). Any existing /Perms is
	// rewritten there, merged with the new /DocMDP entry, so it is skipped here
	// to avoid emitting the key twice.
	writeDocMDP := context.SignData.Signature.CertType == CertificationSignature

	// Copy over existing catalog entries except for type and AcroForum
	for _, key := range root.Keys() {
		if key != "Type" && key != "AcroForm" && !(writeDocMDP && key == "Perms") {
			_, _ = fmt.Fprintf(&catalog_buffer, "  %s ", pdfName(key))
			if err := context.serializeCatalogEntry(&catalog_buffer, rootPtr.GetID(), root.Key(key)); err != nil {
				return nil, fmt.Errorf("failed to serialize catalog entry %q: %w", key, err)
			}
			catalog_buffer.WriteString("\n")
		}
	}

	if writeDocMDP {
		if err := context.writePermsWithDocMDP(&catalog_buffer, root.Key("Perms")); err != nil {
			return nil, err
		}
	}

	// Start the AcroForm dictionary with /NeedAppearances
	catalog_buffer.WriteString("  /AcroForm <<\n")
	catalog_buffer.WriteString("    /Fields [")

	// Add existing fields to the AcroForm dictionary
	fieldsAdded := 0
	acroForm := root.Key("AcroForm")
	if !acroForm.IsNull() {
		fields := acroForm.Key("Fields")
		if !fields.IsNull() && fields.Kind() == pdf.Array {
			for i := 0; i < fields.Len(); i++ {
				ptr := fields.Index(i).GetPtr()
				// Skip direct objects (ID == 0 would emit invalid "0 0 R")
				if ptr.GetID() == 0 {
					continue
				}
				if fieldsAdded > 0 {
					catalog_buffer.WriteString(" ")
				}
				catalog_buffer.WriteString(strconv.Itoa(int(ptr.GetID())) + " 0 R")
				fieldsAdded++
			}
		}
	}

	// Add the visual signature field to the AcroForm dictionary
	if fieldsAdded > 0 {
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
	catalog_buffer.WriteString(">>\n")   // Close Catalog

	return catalog_buffer.Bytes(), nil
}

// writePermsWithDocMDP writes the catalog /Perms dictionary for a certification
// signature, preserving any entries the existing /Perms already carried.
//
// ISO 32000-1 12.8.2.2, "DocMDP":
//
//	A document can contain only one signature field that contains a DocMDP
//	transform method; it shall be the first signed field in the document. The
//	Perms entry in the document catalog dictionary (see 7.7.2, "Document catalog
//	dictionary") shall contain a DocMDP entry whose value is the signature
//	dictionary of that signature field.
//
// Both halves are required. The /P value in the signature dictionary's
// /Reference -> /TransformParams states the permission level, while this /Perms
// entry is what makes a conforming reader apply it. Without /Perms the output is
// read as an ordinary approval signature: Acrobat shows no "Certified by" banner
// and the DocMDP restriction is not enforced.
//
// validateCertificationSignature has already rejected a document that cannot
// take a certification signature, so perms is either null or a dictionary
// without a /DocMDP entry. SignData.objectId holds the signature dictionary's
// object number; it is set by addSignatureObject, which SignPDF runs before
// addCatalog.
func (context *SignContext) writePermsWithDocMDP(w io.Writer, perms pdf.Value) error {
	_, _ = io.WriteString(w, "  /Perms <<\n")

	// Direct values inside /Perms carry the pointer of the object they were
	// read from: the catalog when /Perms is written inline, or the /Perms
	// object itself when it is indirect. serializeCatalogEntry needs that
	// pointer, not the catalog's, to tell them apart from references.
	permsObjId := perms.GetPtr().GetID()
	for _, key := range perms.Keys() {
		_, _ = fmt.Fprintf(w, "    %s ", pdfName(key))
		if err := context.serializeCatalogEntry(w, permsObjId, perms.Key(key)); err != nil {
			return fmt.Errorf("failed to serialize /Perms entry %q: %w", key, err)
		}
		_, _ = io.WriteString(w, "\n")
	}

	_, _ = fmt.Fprintf(w, "    /DocMDP %d 0 R\n", context.SignData.objectId)
	_, _ = io.WriteString(w, "  >>\n")

	return nil
}

// serializeCatalogEntry takes a pdf.Value and serializes it to the given writer.
//
// The reader decodes string escapes and #-encoded name characters, so both are
// re-encoded on the way out: a copied value that contains a delimiter must not
// be able to end its own token and continue as catalog structure.
func (context *SignContext) serializeCatalogEntry(w io.Writer, rootObjId uint32, value pdf.Value) error {
	if ptr := value.GetPtr(); ptr.GetID() > 0 && ptr.GetID() != rootObjId {
		// Indirect object
		_, _ = fmt.Fprintf(w, "%d %d R", ptr.GetID(), ptr.GetGen())
		return nil
	}

	// Direct object
	switch value.Kind() {
	case pdf.String:
		_, _ = io.WriteString(w, pdfLiteralString(value.RawString()))
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
		_, _ = io.WriteString(w, pdfName(value.Name()))
	case pdf.Dict:
		_, _ = fmt.Fprint(w, "<<")
		for idx, key := range value.Keys() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			_, _ = fmt.Fprintf(w, "%s ", pdfName(key))
			if err := context.serializeCatalogEntry(w, rootObjId, value.Key(key)); err != nil {
				return err
			}
		}
		_, _ = fmt.Fprint(w, ">>")
	case pdf.Array:
		_, _ = fmt.Fprint(w, "[")
		for idx := range value.Len() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			if err := context.serializeCatalogEntry(w, rootObjId, value.Index(idx)); err != nil {
				return err
			}
		}
		_, _ = fmt.Fprint(w, "]")
	case pdf.Stream:
		return errors.New("catalog entry: stream cannot be a direct object")
	}
	return nil
}
