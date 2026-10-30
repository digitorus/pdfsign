package sign

import (
	"bytes"
	"fmt"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// fillSignatureField points the existing signature field named by
// SignData.FieldName at the new signature dictionary. The field is rewritten
// in the incremental update with all of its entries kept and /V added. Its
// widgets already sit in the page /Annots, so neither they nor the page are
// touched, and the field stays where it is in the AcroForm field tree.
func (context *SignContext) fillSignatureField() error {
	field, err := context.findSignatureField(context.SignData.FieldName)
	if err != nil {
		return err
	}

	update, err := context.createFilledSignatureField(field)
	if err != nil {
		return err
	}

	fieldObjId := field.GetPtr().GetID()
	if err := context.UpdateObject(fieldObjId, update); err != nil {
		return fmt.Errorf("failed to update signature field %q: %w", context.SignData.FieldName, err)
	}
	context.VisualSignData.objectId = fieldObjId

	return nil
}

// findSignatureField returns the dictionary of the terminal, unsigned
// signature field with the given fully qualified name.
func (context *SignContext) findSignatureField(name string) (pdf.Value, error) {
	var field *acroform.Field
	acroform.Fields(context.PDFReader.Trailer().Key("Root"), func(f acroform.Field) bool {
		if f.Name != name {
			return true
		}
		field = &f
		return false
	})

	switch {
	case field == nil:
		return pdf.Value{}, fmt.Errorf("signature field %q not found", name)
	case field.Type != "Sig":
		return pdf.Value{}, fmt.Errorf("field %q is not a signature field (/FT /%s)", name, field.Type)
	case !field.Terminal:
		return pdf.Value{}, fmt.Errorf("signature field %q has child fields, name one of them instead", name)
	case !field.Value.IsNull():
		return pdf.Value{}, fmt.Errorf("signature field %q is already signed", name)
	case field.Dict.GetPtr().GetID() == 0:
		return pdf.Value{}, fmt.Errorf("signature field %q is a direct object and cannot be updated incrementally", name)
	}

	return field.Dict, nil
}

// createFilledSignatureField serializes the field dictionary with a /V entry
// that references the new signature dictionary.
func (context *SignContext) createFilledSignatureField(field pdf.Value) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<<\n")

	// Direct values carry the field's own pointer, which tells them apart
	// from references to other objects such as /P, /Parent and /AP.
	fieldObjId := field.GetPtr().GetID()
	for _, key := range field.Keys() {
		_, _ = fmt.Fprintf(&buf, "  %s ", pdfName(key))
		if err := context.serializeCatalogEntry(&buf, fieldObjId, field.Key(key)); err != nil {
			return nil, fmt.Errorf("failed to serialize signature field entry %q: %w", key, err)
		}
		buf.WriteString("\n")
	}

	_, _ = fmt.Fprintf(&buf, "  /V %d 0 R\n", context.SignData.objectId)
	buf.WriteString(">>\n")

	return buf.Bytes(), nil
}
