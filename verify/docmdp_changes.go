package verify

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// permissions is what a DocMDP permission level lets an incremental update
// change (ISO 32000-1 Table 254). Every level admits validation data (the
// catalog /DSS and what it references) and document timestamps: PAdES
// (ETSI EN 319 142-1) adds both in incremental updates after signing, a
// certification signature that permits no changes included, and readers
// treat them as validation material rather than as a change to the document.
type permissions struct {
	// level is the /P value the permissions were derived from.
	level int
	// formFilling permits filling in form fields, instantiating page
	// templates, and signing (P=2 and P=3).
	formFilling bool
	// annotations permits creating, deleting and modifying annotations (P=3).
	annotations bool
}

// docMDPPermissions returns the permissions of a /P value. A value outside
// Table 254 is not a permission the signer granted, so it permits nothing.
func docMDPPermissions(p int) permissions {
	switch p {
	case 2:
		return permissions{level: p, formFilling: true}
	case 3:
		return permissions{level: p, formFilling: true, annotations: true}
	}
	return permissions{level: p}
}

// objDefPattern matches a classic PDF indirect object definition header
// ("<id> <gen> obj"), capturing the object number.
var objDefPattern = regexp.MustCompile(`(?:^|[^0-9])([0-9]+)[ \t\r\n\f\x00]+[0-9]+[ \t\r\n\f\x00]+obj\b`)

// maxUpdateSize bounds the bytes of incremental updates that are scanned for
// object definitions.
const maxUpdateSize = 1 << 28

// checkPermittedChanges checks the incremental updates appended after the
// revision a certification signature covers against its DocMDP permissions.
// signed reads that revision and current the whole file.
//
// Every object the updates define is compared with the object as the signed
// revision holds it; a new object changes nothing by itself and is judged
// where a permitted change references it. An object that differs is
// classified by what it was: the catalog, the interactive form dictionary, a
// page, a form field, an annotation, a signature dictionary, validation data,
// the document information dictionary, or anything else, and the difference
// is held against what the permissions allow. The trailer is compared the
// same way, and a page, content stream or resource the signed revision
// reaches must still exist. The first change the permissions do not allow is
// returned as the error.
func checkPermittedChanges(signed, current *pdf.Reader, file io.ReaderAt, fileSize, signedEnd int64, p permissions) error {
	c := &changeChecker{signed: signed, current: current, p: p, exempt: make(map[uint32]bool)}
	for _, trailer := range []pdf.Value{signed.Trailer(), current.Trailer()} {
		if id := trailer.Key("Info").GetPtr().GetID(); id > 0 {
			c.exempt[id] = true
		}
		collectReferences(trailer.Key("Root").Key("DSS"), c.exempt, 0)
	}

	if err := c.trailer(); err != nil {
		return err
	}
	ids, err := updatedObjects(current, file, fileSize, signedEnd)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := c.object(id); err != nil {
			return err
		}
	}
	return c.pageObjectsKept()
}

// updatedObjects returns the numbers of the objects the incremental updates
// after signedEnd may have changed, in order: every object a cross-reference
// section of the updates covers, whether a classic section's subsections or
// a cross-reference stream's /Index (a section can point an object at other
// bytes, or free it, without writing it), every object with a classic
// object header in the update bytes, and the members of every object stream
// among them.
func updatedObjects(current *pdf.Reader, file io.ReaderAt, fileSize, signedEnd int64) ([]uint32, error) {
	updateLen := fileSize - signedEnd
	if updateLen > maxUpdateSize {
		return nil, fmt.Errorf("incremental updates of %d bytes are too large to check against the DocMDP permissions", updateLen)
	}
	buf := make([]byte, updateLen)
	if _, err := file.ReadAt(buf, signedEnd); err != nil {
		return nil, fmt.Errorf("incremental updates could not be read: %w", err)
	}

	seen := make(map[uint32]bool)
	var ids []uint32
	add := func(id uint32) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	addRange := func(start, count int64) error {
		if start < 0 || count < 0 || start+count > maxObjects {
			return fmt.Errorf("incremental update cross-reference section covers objects %d to %d, beyond what can be checked", start, start+count)
		}
		for id := start; id < start+count; id++ {
			add(uint32(id))
		}
		return nil
	}

	for _, section := range classicXrefSections(buf) {
		if err := addRange(section.start, section.count); err != nil {
			return nil, err
		}
	}
	var headers []uint32
	for _, m := range objDefPattern.FindAllSubmatch(buf, -1) {
		id, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			continue
		}
		headers = append(headers, uint32(id))
		add(uint32(id))
	}
	for _, id := range headers {
		v, err := current.GetObject(id)
		if err != nil || v.Kind() != pdf.Stream {
			continue
		}
		switch v.Key("Type").Name() {
		case "ObjStm":
			for _, member := range objectStreamMembers(v) {
				add(member)
			}
		case "XRef":
			index := v.Key("Index")
			if index.Kind() != pdf.Array {
				if err := addRange(0, v.Key("Size").Int64()); err != nil {
					return nil, err
				}
				continue
			}
			for i := 0; i+1 < index.Len(); i += 2 {
				if err := addRange(index.Index(i).Int64(), index.Index(i+1).Int64()); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// maxObjects bounds the object numbers a cross-reference section may cover.
const maxObjects = 1 << 23

// xrefSubsection is a subsection of a classic cross-reference section: the
// first object number it covers and how many.
type xrefSubsection struct {
	start, count int64
}

// xrefKeyword matches the keyword that opens a classic cross-reference
// section at the start of a line.
var xrefKeyword = regexp.MustCompile(`(?m)^xref[ \t\r\n\f\x00]`)

// classicXrefSections returns the subsections of the classic cross-reference
// sections in buf (ISO 32000-1 7.5.4): after the xref keyword, each
// subsection opens with its first object number and entry count and holds
// that many entries, until the trailer keyword.
func classicXrefSections(buf []byte) []xrefSubsection {
	var sections []xrefSubsection
	for _, loc := range xrefKeyword.FindAllIndex(buf, -1) {
		rest := buf[loc[1]:]
		if end := bytes.Index(rest, []byte("trailer")); end >= 0 {
			rest = rest[:end]
		}
		fields := strings.Fields(string(rest))
		for i := 0; i+1 < len(fields); {
			start, err1 := strconv.ParseInt(fields[i], 10, 64)
			count, err2 := strconv.ParseInt(fields[i+1], 10, 64)
			if err1 != nil || err2 != nil || count < 0 || count > maxObjects {
				break
			}
			sections = append(sections, xrefSubsection{start, count})
			i += 2 + 3*int(count)
		}
	}
	return sections
}

// objectStreamMembers returns the numbers of the objects an object stream
// holds, from the pairs of object number and offset that open its data (ISO
// 32000-1 7.5.7).
func objectStreamMembers(stream pdf.Value) []uint32 {
	n, first := stream.Key("N").Int64(), stream.Key("First").Int64()
	if n <= 0 || first <= 0 || first > 1<<24 {
		return nil
	}
	r := stream.Reader()
	defer r.Close()
	header := make([]byte, first)
	read, _ := io.ReadFull(r, header)
	fields := strings.Fields(string(header[:read]))
	var members []uint32
	for i := 0; i+1 < len(fields) && int64(len(members)) < n; i += 2 {
		id, err := strconv.ParseUint(fields[i], 10, 32)
		if err != nil {
			break
		}
		members = append(members, uint32(id))
	}
	return members
}

// collectReferences adds the numbers of the indirect objects reachable from
// v to ids, to a bounded depth.
func collectReferences(v pdf.Value, ids map[uint32]bool, depth int) {
	if depth > 8 {
		return
	}
	visit := func(container, entry pdf.Value) {
		if ptr := entry.GetPtr(); ptr != container.GetPtr() && ptr.GetID() > 0 {
			if ids[ptr.GetID()] {
				return
			}
			ids[ptr.GetID()] = true
		}
		collectReferences(entry, ids, depth+1)
	}
	switch v.Kind() {
	case pdf.Dict, pdf.Stream:
		for _, key := range v.Keys() {
			visit(v, v.Key(key))
		}
	case pdf.Array:
		for i := 0; i < v.Len(); i++ {
			visit(v, v.Index(i))
		}
	}
}

// changeChecker holds the comparison of the signed revision with the
// current document.
type changeChecker struct {
	signed, current *pdf.Reader
	p               permissions
	// exempt holds the objects that may change freely: validation data and
	// the document information dictionary.
	exempt map[uint32]bool
}

func (c *changeChecker) violation(format string, args ...any) error {
	return fmt.Errorf("incremental update %s, which DocMDP P=%d does not permit", fmt.Sprintf(format, args...), c.p.level)
}

// trailer compares the trailers. The entries an update rewrites by nature
// may differ; the catalog is compared when the update replaced it.
func (c *changeChecker) trailer() error {
	old, cur := c.signed.Trailer(), c.current.Trailer()
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "Root":
			if err := c.catalog(old.Key(key), cur.Key(key)); err != nil {
				return err
			}
		case "Info", "Size", "Prev", "XRefStm", "ID", "Type", "W", "Index", "Filter", "DecodeParms", "Length", "DL":
		default:
			return c.violation("changes the trailer entry /%s", key)
		}
	}
	return nil
}

// object compares one object the updates define with the signed revision's.
func (c *changeChecker) object(id uint32) error {
	old := object(c.signed, id)
	if old.IsNull() {
		return nil // A new object changes nothing by itself.
	}
	cur := object(c.current, id)
	if cur.IsNull() {
		return c.removed(id, old)
	}
	if c.exempt[id] || sameObject(old, cur) {
		return nil
	}
	return c.changed(id, old, cur)
}

// object returns the object as the reader holds it, or null.
func object(r *pdf.Reader, id uint32) pdf.Value {
	v, err := r.GetObject(id)
	if err != nil {
		return pdf.Value{}
	}
	return v
}

// sameObject reports whether two objects say the same, references kept.
func sameObject(a, b pdf.Value) bool {
	if canonical(a, 0) != canonical(b, 0) {
		return false
	}
	return a.Kind() != pdf.Stream || bytes.Equal(a.Data(), b.Data())
}

func (c *changeChecker) removed(id uint32, old pdf.Value) error {
	if c.exempt[id] || (c.p.annotations && isAnnotation(old) && !acroform.IsField(old)) {
		return nil
	}
	return c.violation("removes object %d (%s)", id, describe(old))
}

func (c *changeChecker) changed(id uint32, old, cur pdf.Value) error {
	switch {
	case old.Kind() == pdf.Stream && (old.Key("Type").Name() == "ObjStm" || old.Key("Type").Name() == "XRef"):
		return nil // Containers; their members are compared on their own.
	case old.Key("Type").Name() == "Catalog":
		return c.catalog(old, cur)
	case old.Key("Type").Name() == "Page":
		return c.page(id, old, cur)
	case old.Key("Type").Name() == "Pages":
		return c.pagesNode(id, old, cur)
	case acroform.IsSignatureDictionary(old):
		return c.violation("rewrites the signature dictionary %d", id)
	case acroform.IsField(old):
		return c.field(id, old, cur)
	case isAnnotation(old):
		return c.annotation(id, old, cur)
	case isAcroForm(old):
		return c.acroForm(old, cur)
	case old.Key("Type").Name() == "Metadata":
		return nil // Document metadata, which a save rewrites.
	}
	return c.violation("rewrites object %d (%s)", id, describe(old))
}

// catalog compares the document catalog with the signed revision's.
func (c *changeChecker) catalog(old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "AcroForm":
			if err := c.acroForm(old.Key(key), cur.Key(key)); err != nil {
				return err
			}
		case "DSS", "Extensions", "Metadata", "Version":
		default:
			return c.violation("changes the catalog entry /%s", key)
		}
	}
	return nil
}

// acroForm compares the interactive form dictionary with the signed
// revision's: fields may be added by signing, and the entries that describe
// how appearances are built may change with them.
func (c *changeChecker) acroForm(old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "Fields":
			if err := c.fields(old.Key(key), cur.Key(key)); err != nil {
				return err
			}
		case "SigFlags", "DR", "DA", "Q", "NeedAppearances":
		default:
			return c.violation("changes the interactive form entry /%s", key)
		}
	}
	return nil
}

// fields compares the /AcroForm /Fields arrays: no field may go, and a field
// added is a signature field that signing created.
func (c *changeChecker) fields(old, cur pdf.Value) error {
	removed, added := arrayDifference(old, cur)
	if len(removed) > 0 {
		return c.violation("removes a field from /AcroForm /Fields")
	}
	for _, field := range added {
		if !acroform.IsField(field) || fieldType(field) != "Sig" {
			return c.violation("adds a field to /AcroForm /Fields that is not a signature field")
		}
		if !c.signingPermitted(field.Key("V")) {
			return c.violation("adds a signature field")
		}
	}
	return nil
}

// page compares a page with the signed revision's: only its annotations may
// change.
func (c *changeChecker) page(id uint32, old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		if key != "Annots" {
			return c.violation("changes the entry /%s of page object %d", key, id)
		}
		removed, added := arrayDifference(old.Key(key), cur.Key(key))
		if len(removed) > 0 && !c.p.annotations {
			return c.violation("removes an annotation from page object %d", id)
		}
		for _, annot := range added {
			if annot.Kind() != pdf.Dict || annot.Key("Subtype").IsNull() {
				return c.violation("adds an entry to the /Annots of page object %d that is not an annotation", id)
			}
			if c.p.annotations {
				continue
			}
			if annot.Key("Subtype").Name() != "Widget" || fieldType(annot) != "Sig" {
				return c.violation("adds an annotation to page object %d", id)
			}
			if !c.signingPermitted(fieldValue(annot)) {
				return c.violation("adds a signature field to page object %d", id)
			}
		}
	}
	return nil
}

// pagesNode compares a page tree node with the signed revision's: with form
// filling, instantiating a page template appends pages to it (12.7.6).
func (c *changeChecker) pagesNode(id uint32, old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "Kids":
			removed, added := arrayDifference(old.Key(key), cur.Key(key))
			if len(removed) > 0 || !c.p.formFilling {
				return c.violation("changes the pages under page tree node %d", id)
			}
			for _, kid := range added {
				if t := kid.Key("Type").Name(); t != "Page" && t != "Pages" {
					return c.violation("adds an entry to the /Kids of page tree node %d that is not a page", id)
				}
			}
		case "Count":
			if !c.p.formFilling {
				return c.violation("changes the page count of page tree node %d", id)
			}
		default:
			return c.violation("changes the entry /%s of page tree node %d", key, id)
		}
	}
	return nil
}

// field compares a form field with the signed revision's: filling in a form
// sets its value and appearance, and signing sets the value of a signature
// field that had none.
func (c *changeChecker) field(id uint32, old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "V":
			if fieldType(old) == "Sig" {
				if !old.Key("V").IsNull() {
					return c.violation("changes the signature of field %d", id)
				}
				if !c.signingPermitted(cur.Key("V")) {
					return c.violation("signs field %d", id)
				}
			} else if !c.p.formFilling {
				return c.violation("changes the value of field %d", id)
			}
		case "AP", "AS", "I", "DA", "MK", "Ff", "F":
			if !c.p.formFilling {
				return c.violation("changes the entry /%s of field %d", key, id)
			}
		default:
			return c.violation("changes the entry /%s of field %d", key, id)
		}
	}
	return nil
}

// annotation compares an annotation with the signed revision's: a widget's
// appearance follows the value of its field.
func (c *changeChecker) annotation(id uint32, old, cur pdf.Value) error {
	if c.p.annotations {
		return nil
	}
	if old.Key("Subtype").Name() != "Widget" {
		return c.violation("changes annotation %d", id)
	}
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "AP", "AS", "MK", "DA", "F":
			if !c.p.formFilling {
				return c.violation("changes the entry /%s of widget %d", key, id)
			}
		default:
			return c.violation("changes the entry /%s of widget %d", key, id)
		}
	}
	return nil
}

// signingPermitted reports whether a signature with the given value may be
// added: a document timestamp at every level, any other with form filling.
func (c *changeChecker) signingPermitted(value pdf.Value) bool {
	return c.p.formFilling || value.Key("Type").Name() == "DocTimeStamp"
}

// pageObjectsKept checks that every page, content stream and resource the
// signed revision reaches still exists: an update can free an object without
// rewriting what refers to it.
func (c *changeChecker) pageObjectsKept() error {
	protected := make(map[uint32]bool)
	pages := c.signed.Trailer().Key("Root").Key("Pages")
	collectProtectedPageObjects(pages, pages.Key("Resources"), protected, make(map[uint32]bool))
	ids := make([]uint32, 0, len(protected))
	for id := range protected {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if object(c.current, id).IsNull() {
			return c.violation("removes object %d, a page or part of one", id)
		}
	}
	return nil
}

// arrayDifference returns the entries of old that cur lacks and the entries
// of cur that old lacks, resolved. An entry of old that no longer resolves
// counts as removed.
func arrayDifference(old, cur pdf.Value) (removed, added []pdf.Value) {
	entries := func(v pdf.Value) map[string]pdf.Value {
		m := make(map[string]pdf.Value)
		for i := 0; v.Kind() == pdf.Array && i < v.Len(); i++ {
			m[canonicalEntry(v, v.Index(i), 0)] = v.Index(i)
		}
		return m
	}
	oldEntries, curEntries := entries(old), entries(cur)
	for key, v := range oldEntries {
		if _, ok := curEntries[key]; !ok || (v.Kind() == pdf.Dict && curEntries[key].IsNull()) {
			removed = append(removed, v)
		}
	}
	for key, v := range curEntries {
		if _, ok := oldEntries[key]; !ok {
			added = append(added, v)
		}
	}
	return removed, added
}

// unionKeys returns the keys of both dictionaries, sorted.
func unionKeys(a, b pdf.Value) []string {
	seen := make(map[string]bool)
	for _, v := range []pdf.Value{a, b} {
		for _, key := range v.Keys() {
			seen[key] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// fieldType returns the /FT of a field or widget, its own or inherited from
// its parents (Table 220).
func fieldType(v pdf.Value) string {
	for depth := 0; depth <= acroform.MaxDepth && v.Kind() == pdf.Dict; depth++ {
		if ft := v.Key("FT").Name(); ft != "" {
			return ft
		}
		v = v.Key("Parent")
	}
	return ""
}

// fieldValue returns the /V of a field or widget, its own or inherited.
func fieldValue(v pdf.Value) pdf.Value {
	for depth := 0; depth <= acroform.MaxDepth && v.Kind() == pdf.Dict; depth++ {
		if value := v.Key("V"); !value.IsNull() {
			return value
		}
		v = v.Key("Parent")
	}
	return pdf.Value{}
}

// isAnnotation reports whether v is an annotation dictionary: typed as one,
// or a widget.
func isAnnotation(v pdf.Value) bool {
	return v.Kind() == pdf.Dict && (v.Key("Type").Name() == "Annot" || v.Key("Subtype").Name() == "Widget")
}

// isAcroForm reports whether v is an interactive form dictionary: it holds
// the /Fields array and is not a field itself.
func isAcroForm(v pdf.Value) bool {
	return v.Kind() == pdf.Dict && v.Key("Fields").Kind() == pdf.Array && v.Key("Type").IsNull() && !acroform.IsField(v)
}

// describe names an object for a message.
func describe(v pdf.Value) string {
	var parts []string
	if t := v.Key("Type").Name(); t != "" {
		parts = append(parts, "/Type /"+t)
	}
	if s := v.Key("Subtype").Name(); s != "" {
		parts = append(parts, "/Subtype /"+s)
	}
	if len(parts) == 0 {
		switch v.Kind() {
		case pdf.Stream:
			return "a stream"
		case pdf.Dict:
			return "a dictionary"
		default:
			return "a value"
		}
	}
	return strings.Join(parts, " ")
}
