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
	c := &changeChecker{signed: signed, current: current, p: p, exempt: make(map[uint32]bool), roles: make(map[uint32]role)}
	// What may change freely is decided by the signed revision alone: what
	// the update's catalog or trailer point at is the attacker's to choose.
	trailer := signed.Trailer()
	if id := trailer.Key("Info").GetPtr().GetID(); id > 0 {
		c.exempt[id] = true
	}
	root := trailer.Key("Root")
	if dss := root.Key("DSS"); dss.GetPtr() != root.GetPtr() && dss.GetPtr().GetID() > 0 {
		c.exempt[dss.GetPtr().GetID()] = true
	}
	collectReferences(root.Key("DSS"), c.exempt, 0)
	c.templates = !root.Key("Names").Key("Templates").IsNull()
	c.collectRoles(root)

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

	for _, section := range xrefSections(buf) {
		if err := addRange(section.start, section.count); err != nil {
			return nil, err
		}
	}
	for _, h := range objectHeaders(buf) {
		add(h.id)
		if v, err := current.GetObject(h.id); err == nil && v.Kind() == pdf.Stream && v.Key("Type").Name() == "ObjStm" {
			for _, member := range objectStreamMembers(v) {
				add(member)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// maxObjects bounds the object numbers a cross-reference section may cover.
const maxObjects = 1 << 23

// xrefSubsection is a range of objects a cross-reference section covers: the
// first object number and how many.
type xrefSubsection struct {
	start, count int64
}

// objectHeader is a classic indirect object header ("id gen obj") in a
// byte slice: the object number and the offset just past the keyword.
type objectHeader struct {
	id  uint32
	end int
}

// objectHeaders returns the object headers in buf, in order: an obj keyword
// on its own, preceded by a generation and an object number that no digit
// precedes (ISO 32000-1 7.3.10).
func objectHeaders(buf []byte) []objectHeader {
	var headers []objectHeader
	for i := 0; ; {
		j := bytes.Index(buf[i:], []byte("obj"))
		if j < 0 {
			return headers
		}
		at := i + j
		i = at + 3
		if i < len(buf) && isRegular(buf[i]) {
			continue
		}
		p := at - 1
		digits := func() (int64, bool) {
			end := p
			for p >= 0 && buf[p] >= '0' && buf[p] <= '9' {
				p--
			}
			if p == end {
				return 0, false
			}
			n, err := strconv.ParseInt(string(buf[p+1:end+1]), 10, 64)
			return n, err == nil
		}
		whitespace := func() bool {
			end := p
			for p >= 0 && isPDFWhitespace(buf[p]) {
				p--
			}
			return p < end
		}
		if !whitespace() {
			continue
		}
		if _, ok := digits(); !ok || !whitespace() {
			continue
		}
		id, ok := digits()
		if !ok || id < 0 || id > maxObjects {
			continue
		}
		headers = append(headers, objectHeader{uint32(id), i})
	}
}

// isRegular reports whether b is a regular character: neither white space
// nor a delimiter (7.2.2).
func isRegular(b byte) bool {
	return !isPDFWhitespace(b) && !strings.ContainsRune("()<>[]{}/%", rune(b))
}

// xrefKeywords returns the offsets just past every xref keyword that opens
// a line in buf.
func xrefKeywords(buf []byte) []int {
	var ends []int
	for i := 0; ; {
		j := bytes.Index(buf[i:], []byte("xref"))
		if j < 0 {
			return ends
		}
		at := i + j
		i = at + 4
		if (at == 0 || buf[at-1] == '\n' || buf[at-1] == '\r') && i < len(buf) && isPDFWhitespace(buf[i]) {
			ends = append(ends, i)
		}
	}
}

var (
	// nameEscape matches a #xx escape in a name.
	nameEscape = regexp.MustCompile(`#([0-9A-Fa-f]{2})`)
	xrefType   = regexp.MustCompile(`/Type[ \t\r\n\f\x00]*/XRef\b`)
	xrefIndex  = regexp.MustCompile(`/Index[ \t\r\n\f\x00]*\[([^\]]*)\]`)
	xrefSize   = regexp.MustCompile(`/Size[ \t\r\n\f\x00]+([0-9]+)`)
)

// xrefSections returns the ranges of objects the cross-reference sections in
// buf cover, read from the bytes rather than through the reader so that a
// section counts whether or not the document resolves it: the subsections of
// every classic section (ISO 32000-1 7.5.4), and the /Index of every
// cross-reference stream (7.5.8), or its /Size when it has none.
func xrefSections(buf []byte) []xrefSubsection {
	var sections []xrefSubsection
	for _, end := range xrefKeywords(buf) {
		scan := tokens{buf: buf, pos: end}
		for {
			start, ok1 := scan.int()
			count, ok2 := scan.int()
			if !ok1 || !ok2 || count < 0 || count > maxObjects {
				break
			}
			sections = append(sections, xrefSubsection{start, count})
			for i := int64(0); i < 3*count; i++ {
				if _, ok := scan.next(); !ok {
					break
				}
			}
		}
	}
	for _, h := range objectHeaders(buf) {
		dict, ok := streamDictionary(buf[h.end:])
		if !ok {
			continue
		}
		dict = nameEscape.ReplaceAllFunc(dict, func(escape []byte) []byte {
			b, _ := strconv.ParseUint(string(escape[1:]), 16, 8)
			return []byte{byte(b)}
		})
		if !xrefType.Match(dict) {
			continue
		}
		if index := xrefIndex.FindSubmatch(dict); index != nil {
			fields := strings.Fields(string(index[1]))
			for i := 0; i+1 < len(fields); i += 2 {
				start, err1 := strconv.ParseInt(fields[i], 10, 64)
				count, err2 := strconv.ParseInt(fields[i+1], 10, 64)
				if err1 != nil || err2 != nil {
					break
				}
				sections = append(sections, xrefSubsection{start, count})
			}
		} else if size := xrefSize.FindSubmatch(dict); size != nil {
			count, _ := strconv.ParseInt(string(size[1]), 10, 64)
			sections = append(sections, xrefSubsection{0, count})
		}
	}
	return sections
}

// maxStreamDictionary bounds the dictionary of a cross-reference stream.
const maxStreamDictionary = 1 << 16

// streamDictionary returns the dictionary that opens an indirect object
// which is a stream: the bytes from the object header to the stream keyword,
// when they form a dictionary of bounded size.
func streamDictionary(after []byte) ([]byte, bool) {
	window := after[:min(len(after), maxStreamDictionary)]
	end := bytes.Index(window, []byte("stream"))
	if end < 0 {
		return nil, false
	}
	dict := bytes.TrimLeft(window[:end], " \t\r\n\f\x00")
	dict = bytes.TrimRight(dict, " \t\r\n\f\x00")
	if !bytes.HasPrefix(dict, []byte("<<")) || !bytes.HasSuffix(dict, []byte(">>")) {
		return nil, false
	}
	return dict, true
}

// tokens reads whitespace-separated tokens from a byte slice, stopping at
// the trailer keyword.
type tokens struct {
	buf []byte
	pos int
}

func isPDFWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' || b == 0
}

func (t *tokens) next() ([]byte, bool) {
	for t.pos < len(t.buf) && isPDFWhitespace(t.buf[t.pos]) {
		t.pos++
	}
	start := t.pos
	for t.pos < len(t.buf) && !isPDFWhitespace(t.buf[t.pos]) {
		t.pos++
	}
	token := t.buf[start:t.pos]
	if len(token) == 0 || bytes.Equal(token, []byte("trailer")) {
		return nil, false
	}
	return token, true
}

func (t *tokens) int() (int64, bool) {
	token, ok := t.next()
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(token), 10, 64)
	return n, err == nil
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
	// exempt holds the objects that may change freely: the signed
	// revision's validation data and document information dictionary.
	exempt map[uint32]bool
	// roles holds, for the untyped objects the signed revision's form and
	// pages reach, the entry that reaches them, which decides what may
	// change in them.
	roles map[uint32]role
	// templates is whether the signed document defines page templates, so
	// that instantiating one may append a page.
	templates bool
}

// roleKind is the entry of a form, field, widget or page that reaches an
// untyped object: an array or dictionary that says nothing about itself.
type roleKind int

const (
	roleFields     roleKind = iota + 1 // the interactive form's /Fields, or a field's /Kids
	roleAnnots                         // a page's /Annots
	roleAppearance                     // a field's or widget's /AP or /MK, or a form's /DR
	roleValue                          // a field's /V, other than a signature
)

// role is what reaches an untyped object.
type role struct {
	kind  roleKind
	owner uint32 // the object holding the entry, for the message
}

// collectRoles records the untyped objects the signed revision's pages and
// interactive form reach through entries that may change.
func (c *changeChecker) collectRoles(root pdf.Value) {
	note := func(container, entry pdf.Value, kind roleKind) {
		if ptr := entry.GetPtr(); ptr != container.GetPtr() && ptr.GetID() > 0 && entry.Kind() != pdf.Stream {
			if _, ok := c.roles[ptr.GetID()]; !ok {
				c.roles[ptr.GetID()] = role{kind: kind, owner: container.GetPtr().GetID()}
			}
		}
	}
	var pages func(node pdf.Value, depth int)
	visited := make(map[uint32]bool)
	pages = func(node pdf.Value, depth int) {
		id := node.GetPtr().GetID()
		if depth > acroform.MaxDepth || node.Kind() != pdf.Dict || visited[id] {
			return
		}
		visited[id] = true
		if kids := node.Key("Kids"); kids.Kind() == pdf.Array {
			for i := 0; i < kids.Len(); i++ {
				pages(kids.Index(i), depth+1)
			}
			return
		}
		note(node, node.Key("Annots"), roleAnnots)
		annots := node.Key("Annots")
		for i := 0; annots.Kind() == pdf.Array && i < annots.Len(); i++ {
			annot := annots.Index(i)
			note(annot, annot.Key("AP"), roleAppearance)
			note(annot, annot.Key("MK"), roleAppearance)
		}
	}
	pages(root.Key("Pages"), 0)

	form := root.Key("AcroForm")
	note(form, form.Key("Fields"), roleFields)
	note(form, form.Key("DR"), roleAppearance)
	var fields func(kids pdf.Value, depth int)
	fields = func(kids pdf.Value, depth int) {
		for i := 0; depth <= acroform.MaxDepth && kids.Kind() == pdf.Array && i < kids.Len(); i++ {
			field := kids.Index(i)
			id := field.GetPtr().GetID()
			if field.Kind() != pdf.Dict || visited[id] {
				continue
			}
			visited[id] = true
			note(field, field.Key("Kids"), roleFields)
			note(field, field.Key("AP"), roleAppearance)
			note(field, field.Key("MK"), roleAppearance)
			note(field, field.Key("DR"), roleAppearance)
			if fieldType(field) != "Sig" {
				note(field, field.Key("V"), roleValue)
			}
			fields(field.Key("Kids"), depth+1)
		}
	}
	fields(form.Key("Fields"), 0)
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
	if r, ok := c.roles[id]; ok {
		return c.container(id, r, old, cur)
	}
	return c.violation("rewrites object %d (%s)", id, describe(old))
}

// container compares an untyped object by the entry that reaches it.
func (c *changeChecker) container(id uint32, r role, old, cur pdf.Value) error {
	switch r.kind {
	case roleFields:
		return c.fields(old, cur)
	case roleAnnots:
		return c.annots(r.owner, old, cur)
	case roleAppearance:
		if !c.p.formFilling {
			return c.violation("changes the appearance object %d of object %d", id, r.owner)
		}
	case roleValue:
		if !c.p.formFilling {
			return c.violation("changes the value of field %d", r.owner)
		}
	}
	return nil
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
		if err := c.annots(id, old.Key(key), cur.Key(key)); err != nil {
			return err
		}
	}
	return nil
}

// annots compares the /Annots of a page: an annotation may be added or
// removed with annotation permissions, and a signature widget by signing.
func (c *changeChecker) annots(page uint32, old, cur pdf.Value) error {
	removed, added := arrayDifference(old, cur)
	if len(removed) > 0 && !c.p.annotations {
		return c.violation("removes an annotation from page object %d", page)
	}
	for _, annot := range added {
		if annot.Kind() != pdf.Dict || annot.Key("Subtype").IsNull() {
			return c.violation("adds an entry to the /Annots of page object %d that is not an annotation", page)
		}
		if c.p.annotations {
			continue
		}
		if annot.Key("Subtype").Name() != "Widget" || fieldType(annot) != "Sig" {
			return c.violation("adds an annotation to page object %d", page)
		}
		if !c.signingPermitted(fieldValue(annot)) {
			return c.violation("adds a signature field to page object %d", page)
		}
	}
	return nil
}

// pagesNode compares a page tree node with the signed revision's: with form
// filling, instantiating a page template the signed document defines (12.7.6,
// the catalog /Names /Templates) appends pages to it.
func (c *changeChecker) pagesNode(id uint32, old, cur pdf.Value) error {
	for _, key := range unionKeys(old, cur) {
		if canonicalEntry(old, old.Key(key), 0) == canonicalEntry(cur, cur.Key(key), 0) {
			continue
		}
		switch key {
		case "Kids":
			removed, added := arrayDifference(old.Key(key), cur.Key(key))
			if len(removed) > 0 || !c.p.formFilling || !c.templates {
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
