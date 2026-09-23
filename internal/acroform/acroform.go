// Package acroform walks the interactive form field tree of a document
// (ISO 32000-1 12.7.3, "Field dictionaries").
package acroform

import "github.com/digitorus/pdf"

// MaxDepth bounds the field tree walk; a conforming document nests fields far
// less deeply, and a crafted one must not recurse without end.
const MaxDepth = 64

// SignatureFields calls fn for every terminal signature field below the
// document catalog root, in document order, until fn returns false.
//
// A field takes its /FT from its ancestors when it has none of its own, since
// the entry is inheritable (Table 220), and so is /V: a field that carries a
// value is reported itself rather than walked into, as its child fields would
// only inherit that value. The kids of a terminal field are its widget
// annotations rather than fields, so a signed field with several widgets is
// reported once, while an untitled intermediate node is walked like any other
// field: /T is optional. A visited set and a depth bound keep a crafted /Kids
// cycle from recursing without end.
func SignatureFields(root pdf.Value, fn func(field pdf.Value) bool) {
	walk(root.Key("AcroForm").Key("Fields"), "", make(map[pdf.Ptr]bool), 0, fn)
}

func walk(kids pdf.Value, inheritedFT string, visited map[pdf.Ptr]bool, depth int, fn func(pdf.Value) bool) bool {
	if kids.Kind() != pdf.Array || depth > MaxDepth {
		return true
	}
	for i := 0; i < kids.Len(); i++ {
		field := kids.Index(i)
		if !IsField(field) {
			continue
		}
		// A dictionary written directly into the array carries the array's
		// own pointer, so only an indirect object identifies a node.
		if ptr := field.GetPtr(); ptr != kids.GetPtr() {
			if visited[ptr] {
				continue
			}
			visited[ptr] = true
		}

		ft := field.Key("FT").Name()
		if ft == "" {
			ft = inheritedFT
		}

		if children := field.Key("Kids"); field.Key("V").IsNull() && hasFields(children) {
			if !walk(children, ft, visited, depth+1, fn) {
				return false
			}
			continue
		}
		if ft == "Sig" && !fn(field) {
			return false
		}
	}
	return true
}

// IsField reports whether v is a field dictionary rather than a widget
// annotation: a field carries at least one of the entries a widget does not.
func IsField(v pdf.Value) bool {
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
		if IsField(kids.Index(i)) {
			return true
		}
	}
	return false
}

// IsSignatureDictionary reports whether v is a signature dictionary (ISO
// 32000-1 Table 252): one typed as a signature or a document timestamp, or
// one that names its handler and carries signature bytes.
func IsSignatureDictionary(v pdf.Value) bool {
	if v.Kind() != pdf.Dict {
		return false
	}
	switch v.Key("Type").Name() {
	case "Sig", "DocTimeStamp":
		return true
	}
	return !v.Key("Filter").IsNull() && !v.Key("Contents").IsNull()
}
