package forms

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// escapePDFString escapes special characters in a PDF literal string.
// PDF literal strings are delimited by parentheses; backslashes, unbalanced
// parentheses, and carriage-returns must be escaped to avoid corrupting the
// object stream.
func escapePDFString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FormField represents a form field in the document.
type FormField struct {
	Name  string
	Type  string // "text", "checkbox", "radio", "signature"
	Value any
}

// Extract returns the terminal form fields of the PDF (ISO 32000-1 12.7.3),
// with their fully qualified names and the /FT and /V they carry or inherit.
func Extract(r *pdf.Reader) []FormField {
	if r == nil {
		return nil
	}

	var result []FormField
	acroform.Fields(r.Trailer().Key("Root"), func(f acroform.Field) bool {
		if !f.Terminal || f.Type == "" {
			return true
		}
		var strVal string
		if f.Value.Kind() == pdf.String {
			strVal = f.Value.RawString()
		} else {
			strVal = f.Value.String()
		}
		result = append(result, FormField{
			Name:  f.Name,
			Type:  f.Type,
			Value: strVal,
		})
		return true
	})

	return result
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
		// Copy the entry: an indirect object stays a reference (a direct
		// entry carries the field's own pointer, and a reference that does
		// not resolve none), so a parent, appearance or resource is neither
		// duplicated nor turned into a copy.
		entry := v.Key(key)
		if entryPtr := entry.GetPtr(); entryPtr != ptr && entryPtr.GetID() > 0 {
			fmt.Fprintf(&buf, "  /%s %d %d R\n", key, entryPtr.GetID(), entryPtr.GetGen())
			continue
		}
		fmt.Fprintf(&buf, "  /%s %s\n", key, entry.String())
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
		fmt.Fprintf(&buf, "  /V (%s)\n", escapePDFString(val))
	case int, int64, float64:
		fmt.Fprintf(&buf, "  /V %v\n", val)
	default:
		fmt.Fprintf(&buf, "  /V (%s)\n", escapePDFString(fmt.Sprintf("%v", val)))
	}
	buf.WriteString(">>")

	return buf.Bytes(), nil
}

// MapFields maps the fully qualified names of the field v and every typed
// field below it to their dictionaries. prefix is the name of v's parent, or
// "" for a top-level field.
func MapFields(v pdf.Value, prefix string, m map[string]pdf.Value) {
	acroform.FieldsOf(v, prefix, func(f acroform.Field) bool {
		if f.Type != "" {
			m[f.Name] = f.Dict
		}
		return true
	})
}
