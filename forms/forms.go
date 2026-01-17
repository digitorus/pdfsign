package forms

import (
	"bytes"
	"fmt"

	"github.com/digitorus/pdf"
)

// FormField represents a form field in the document.
type FormField struct {
	Name  string
	Type  string // "text", "checkbox", "radio", "signature"
	Value any
}

// Extract returns all form fields found in the PDF.
func Extract(r *pdf.Reader) []FormField {
	if r == nil {
		return nil
	}

	root := r.Trailer().Key("Root")
	acroForm := root.Key("AcroForm")
	if acroForm.IsNull() {
		return nil
	}

	fields := acroForm.Key("Fields")
	if fields.IsNull() || fields.Kind() != pdf.Array {
		return nil
	}

	var result []FormField
	for i := 0; i < fields.Len(); i++ {
		result = append(result, extractFieldsRec(fields.Index(i), "")...)
	}

	return result
}

func extractFieldsRec(v pdf.Value, prefix string) []FormField {
	if v.IsNull() {
		return nil
	}

	name := v.Key("T").RawString()
	if prefix != "" {
		name = prefix + "." + name
	}

	// If it's a leaf field (has /FT)
	ft := v.Key("FT").Name()
	if ft != "" {
		val := v.Key("V")
		var strVal string
		if val.Kind() == pdf.String {
			strVal = val.RawString()
		} else {
			strVal = val.String()
		}

		field := FormField{
			Name:  name,
			Type:  ft,
			Value: strVal,
		}
		return []FormField{field}
	}

	// If it has kids, recurse
	kids := v.Key("Kids")
	if kids.Kind() == pdf.Array {
		var result []FormField
		for i := 0; i < kids.Len(); i++ {
			result = append(result, extractFieldsRec(kids.Index(i), name)...)
		}
		return result
	}

	return nil
}

// GenerateUpdate generates a PDF object update for a field value change.
func GenerateUpdate(v pdf.Value, value any) ([]byte, error) {
	ptr := v.GetPtr()
	if ptr.GetID() == 0 {
		return nil, fmt.Errorf("field has no object pointer")
	}

	var buf bytes.Buffer
	buf.WriteString("<<\n")
	for _, key := range v.Keys() {
		if key == "V" {
			continue // Skip old value
		}
		// Copy existing key-value
		fmt.Fprintf(&buf, "  /%s %s\n", key, v.Key(key).String())
	}

	// Add/Update value
	switch val := value.(type) {
	case bool:
		if val {
			fmt.Fprintf(&buf, "  /V /Yes\n")
		} else {
			fmt.Fprintf(&buf, "  /V /Off\n")
		}
	case string:
		fmt.Fprintf(&buf, "  /V (%s)\n", val)
	case int, int64, float64:
		fmt.Fprintf(&buf, "  /V %v\n", val)
	default:
		fmt.Fprintf(&buf, "  /V (%v)\n", val)
	}
	buf.WriteString(">>")

	return buf.Bytes(), nil
}

// MapFields maps field names to their PDF values.
func MapFields(v pdf.Value, prefix string, m map[string]pdf.Value) {
	if v.IsNull() {
		return
	}

	name := v.Key("T").RawString()
	if prefix != "" {
		name = prefix + "." + name
	}

	if v.Key("FT").Name() != "" {
		m[name] = v
	}

	kids := v.Key("Kids")
	if kids.Kind() == pdf.Array {
		for i := 0; i < kids.Len(); i++ {
			MapFields(kids.Index(i), name, m)
		}
	}
}
