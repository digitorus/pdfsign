// Package acroform walks the interactive form field tree of a document
// (ISO 32000-1 12.7.3, "Field dictionaries").
package acroform

import "github.com/digitorus/pdf"

// MaxDepth bounds the field tree walk; a conforming document nests fields far
// less deeply, and a crafted one must not recurse without end.
const MaxDepth = 64

// Field is a field reached by the walk, with the inheritable entries it may
// take from its ancestors resolved.
type Field struct {
	// Dict is the field dictionary.
	Dict pdf.Value
	// Name is the fully qualified field name: the partial names (/T) of the
	// field and its ancestors joined with periods (12.7.3.2).
	Name string
	// Type is the field type (/FT), the field's own or inherited.
	Type string
	// Value is the field value (/V), the field's own or inherited.
	Value pdf.Value
	// Terminal is set when the field has no field kids (12.7.3.1); any kids
	// it has are its widget annotations.
	Terminal bool
}

// Fields calls fn for every field below the document catalog root, a parent
// before its kids, in document order, until fn returns false.
//
// /FT and /V are inheritable (Table 220): a field takes either from its
// ancestors when it has none of its own. Kids that carry none of the entries
// a field has are widget annotations rather than fields, so a field with
// several widgets is reported once and is terminal, while an untitled
// intermediate node is walked like any other field: /T is optional. A visited
// set and a depth bound keep a crafted /Kids cycle from recursing without end.
func Fields(root pdf.Value, fn func(Field) bool) {
	walk(root.Key("AcroForm").Key("Fields"), Field{}, make(map[visit]bool), 0, visitor{visit: fn})
}

// FieldsOf calls fn for the given field and every field below it, a parent
// before its kids, until fn returns false. prefix is the fully qualified name
// of the field's parent, or "" for a top-level field; entries the field would
// inherit from above it are not available here.
func FieldsOf(field pdf.Value, prefix string, fn func(Field) bool) {
	node(field, pdf.Value{}, Field{Name: prefix}, make(map[visit]bool), 0, visitor{visit: fn})
}

// SignatureFields calls fn for every signature field below the document
// catalog root that holds, or may hold, a signature, in document order, until
// fn returns false: the terminal signature fields, and a signature field that
// carries its own /V, which is the signed field and is not walked into, as
// its kids would only inherit that value.
func SignatureFields(root pdf.Value, fn func(field pdf.Value) bool) {
	signed := func(f Field) bool { return f.Type == "Sig" && !f.Dict.Key("V").IsNull() }
	walk(root.Key("AcroForm").Key("Fields"), Field{}, make(map[visit]bool), 0, visitor{
		visit: func(f Field) bool {
			if f.Type == "Sig" && (f.Terminal || signed(f)) {
				return fn(f.Dict)
			}
			return true
		},
		descend: func(f Field) bool { return !signed(f) },
	})
}

// visitor receives the fields of a walk: visit reports whether the walk goes
// on, descend whether the walk enters a field's kids (always, when nil).
type visitor struct {
	visit   func(Field) bool
	descend func(Field) bool
}

// visit identifies a node of the walk. A conforming field has one parent, but
// a crafted tree can reach the same object under parents that pass down
// different types; it is then walked once per type, so a signature field is
// found however it is reached, while a cycle still ends.
type visit struct {
	ptr pdf.Ptr
	typ string
}

func walk(kids pdf.Value, parent Field, visited map[visit]bool, depth int, vis visitor) bool {
	if kids.Kind() != pdf.Array || depth > MaxDepth {
		return true
	}
	for i := 0; i < kids.Len(); i++ {
		if !node(kids.Index(i), kids, parent, visited, depth, vis) {
			return false
		}
	}
	return true
}

// node visits one entry of a /Fields or /Kids array. container is that array,
// or a null value when the entry is visited on its own.
func node(field, container pdf.Value, parent Field, visited map[visit]bool, depth int, vis visitor) bool {
	if !isField(field) {
		return true
	}
	f := Field{Dict: field, Name: parent.Name, Type: field.Key("FT").Name(), Value: field.Key("V")}
	if f.Type == "" {
		f.Type = parent.Type
	}
	// A dictionary written directly into the array carries the array's own
	// pointer, so only an indirect object identifies a node.
	if ptr := field.GetPtr(); container.IsNull() || ptr != container.GetPtr() {
		key := visit{ptr, f.Type}
		if visited[key] {
			return true
		}
		visited[key] = true
	}
	if f.Value.IsNull() {
		f.Value = parent.Value
	}
	if partial := field.Key("T").Text(); partial != "" {
		if f.Name != "" {
			f.Name += "."
		}
		f.Name += partial
	}
	children := field.Key("Kids")
	f.Terminal = !hasFields(children)

	if !vis.visit(f) {
		return false
	}
	if f.Terminal || (vis.descend != nil && !vis.descend(f)) {
		return true
	}
	return walk(children, f, visited, depth+1, vis)
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
