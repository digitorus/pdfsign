// Package acroform walks the interactive form field tree of a document
// (ISO 32000-1 12.7.3, "Field dictionaries").
package acroform

import "github.com/digitorus/pdf"

// MaxDepth bounds the field tree walk; a conforming document nests fields far
// less deeply, and a crafted one must not recurse without end.
const MaxDepth = 64

// Field is a terminal field reached by the walk, with the inheritable entries
// it may take from its ancestors resolved.
type Field struct {
	// Value is the field dictionary.
	Value pdf.Value
	// Name is the fully qualified field name: the partial names (/T) of the
	// field and its ancestors joined with periods (12.7.3.2).
	Name string
	// Type is the field type (/FT), the field's own or inherited.
	Type string
}

// Fields calls fn for every terminal field below the document catalog root,
// in document order, until fn returns false.
//
// A field takes its /FT from its ancestors when it has none of its own, since
// the entry is inheritable (Table 220), and so is /V: a field that carries a
// value is reported itself rather than walked into, as its child fields would
// only inherit that value. The kids of a terminal field are its widget
// annotations rather than fields, so a field with several widgets is reported
// once, while an untitled intermediate node is walked like any other field:
// /T is optional. A visited set and a depth bound keep a crafted /Kids cycle
// from recursing without end.
func Fields(root pdf.Value, fn func(Field) bool) {
	walk(root.Key("AcroForm").Key("Fields"), Field{}, make(map[pdf.Ptr]bool), 0, fn)
}

// FieldsOf calls fn for every terminal field at or below the given field
// dictionary, until fn returns false. prefix is the fully qualified name of
// the field's parent, or "" for a top-level field.
func FieldsOf(field pdf.Value, prefix string, fn func(Field) bool) {
	node(field, pdf.Value{}, Field{Name: prefix}, make(map[pdf.Ptr]bool), 0, fn)
}

// SignatureFields calls fn for every terminal signature field below the
// document catalog root, in document order, until fn returns false.
func SignatureFields(root pdf.Value, fn func(field pdf.Value) bool) {
	Fields(root, func(f Field) bool {
		if f.Type != "Sig" {
			return true
		}
		return fn(f.Value)
	})
}

func walk(kids pdf.Value, parent Field, visited map[pdf.Ptr]bool, depth int, fn func(Field) bool) bool {
	if kids.Kind() != pdf.Array || depth > MaxDepth {
		return true
	}
	for i := 0; i < kids.Len(); i++ {
		if !node(kids.Index(i), kids, parent, visited, depth, fn) {
			return false
		}
	}
	return true
}

// node visits one entry of a /Fields or /Kids array. container is that array,
// or a null value when the entry is visited on its own.
func node(field, container pdf.Value, parent Field, visited map[pdf.Ptr]bool, depth int, fn func(Field) bool) bool {
	if !isField(field) {
		return true
	}
	// A dictionary written directly into the array carries the array's own
	// pointer, so only an indirect object identifies a node.
	if ptr := field.GetPtr(); container.IsNull() || ptr != container.GetPtr() {
		if visited[ptr] {
			return true
		}
		visited[ptr] = true
	}

	f := Field{Value: field, Name: parent.Name, Type: field.Key("FT").Name()}
	if f.Type == "" {
		f.Type = parent.Type
	}
	if partial := field.Key("T").RawString(); partial != "" {
		if f.Name != "" {
			f.Name += "."
		}
		f.Name += partial
	}

	if children := field.Key("Kids"); field.Key("V").IsNull() && hasFields(children) {
		return walk(children, f, visited, depth+1, fn)
	}
	return fn(f)
}

// isField reports whether v is a field dictionary rather than a widget
// annotation: a field carries at least one of the entries a widget does not.
func isField(v pdf.Value) bool {
	if v.Kind() != pdf.Dict {
		return false
	}
	for _, key := range []string{"T", "FT", "V", "Kids"} {
		if !v.Key(key).IsNull() {
			return true
		}
	}
	return false
}

// hasFields reports whether the /Kids array holds any field dictionary.
func hasFields(kids pdf.Value) bool {
	for i := 0; kids.Kind() == pdf.Array && i < kids.Len(); i++ {
		if isField(kids.Index(i)) {
			return true
		}
	}
	return false
}
