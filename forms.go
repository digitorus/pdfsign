package pdfsign

import (
	"fmt"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/forms"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// FormFields returns all form fields in the document.
func (d *Document) FormFields() []FormField {
	return forms.Extract(d.rdr)
}

// SetField sets the value of a form field.
func (d *Document) SetField(name string, value any) error {
	// Staging field updates to be applied during Write()
	if d.pendingFields == nil {
		d.pendingFields = make(map[string]any)
	}
	d.pendingFields[name] = value
	return nil
}

// SetFields sets multiple form field values.
func (d *Document) SetFields(fields map[string]any) error {
	for name, value := range fields {
		if err := d.SetField(name, value); err != nil {
			return err
		}
	}
	return nil
}

// applyPendingFields resolves pending field updates to object IDs and generated content.
func (d *Document) applyPendingFields() (map[uint32][]byte, error) {
	if len(d.pendingFields) == 0 {
		return nil, nil
	}

	updates := make(map[uint32][]byte)

	// Map field names to their PDF values
	fieldMap := make(map[string]pdf.Value)
	acroform.Fields(d.rdr.Trailer().Key("Root"), func(f acroform.Field) bool {
		if f.Type != "" {
			fieldMap[f.Name] = f.Dict
		}
		return true
	})

	for name, value := range d.pendingFields {
		v, ok := fieldMap[name]
		if !ok {
			return nil, fmt.Errorf("field %s not found in document", name)
		}

		update, err := forms.GenerateUpdate(v, value)
		if err != nil {
			return nil, err
		}

		ptr := v.GetPtr()
		updates[ptr.GetID()] = update
	}

	return updates, nil
}
