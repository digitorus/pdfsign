package sign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
)

// objectEncrypter encrypts string and stream data of an indirect object with
// the security handler of the document and gives access to the trailer, which
// says which object holds the encryption dictionary and which crypt filters it
// defines. *pdf.Reader implements it.
type objectEncrypter interface {
	Encrypt(ptr pdf.Ptr, data []byte) ([]byte, error)
	EncryptsMetadata() bool
	Trailer() pdf.Value
}

type objTokenKind int

const (
	tokOther objTokenKind = iota // copied as is: numbers, keywords, delimiters, whitespace
	tokName
	tokString // literal or hexadecimal string
	tokDictOpen
	tokDictClose
	tokArrayOpen
	tokArrayClose
	tokStream // stream data between "stream<EOL>" and "<EOL>endstream"
)

type objToken struct {
	kind       objTokenKind
	start, end int    // byte range in the source object
	value      []byte // decoded string, name without the slash, or encrypted stream data
	depth      int    // dictionary nesting depth; 1 is the object's top-level dictionary
	key        string // for dictionary values, the key the value belongs to
}

// encryptObject returns the body of indirect object id with every string and
// stream encrypted for an encrypted document, as required by ISO 32000-1,
// 7.6.1. Strings are written as hexadecimal strings. Not encrypted are the
// encryption dictionary, whose strings the security handler reads to derive
// the key, the Contents of a signature or document timestamp dictionary
// (7.6.2), whose placeholder is filled in after signing, cross-reference
// streams (7.5.8) and the streams that streamEncrypted excludes. If enc is nil
// the object is returned unchanged.
func encryptObject(enc objectEncrypter, id uint32, object []byte) ([]byte, error) {
	if enc == nil {
		return object, nil
	}
	// Encrypting it would destroy the values its own key is derived from, and
	// the document would no longer open with any password.
	if ptr := enc.Trailer().Key("Encrypt").GetPtr(); id != 0 && ptr.GetID() == id {
		return object, nil
	}
	tokens, err := tokenizeObject(object)
	if err != nil {
		return nil, fmt.Errorf("object %d: %w", id, err)
	}

	top := topLevelValues(tokens)
	if name, ok := top["Type"]; ok && name.kind == tokName && string(name.value) == "XRef" {
		return object, nil
	}
	isSignature := false
	if name, ok := top["Type"]; ok && name.kind == tokName {
		isSignature = string(name.value) == "Sig" || string(name.value) == "DocTimeStamp"
	}
	if _, hasByteRange := top["ByteRange"]; hasByteRange {
		if _, hasFilter := top["Filter"]; hasFilter {
			isSignature = true
		}
	}

	ptr := pdf.NewPtr(id, 0)
	out := make([]byte, 0, len(object)+len(object)/2)
	lengthToken := -1
	if length, ok := top["Length"]; ok {
		lengthToken = length.index
	}
	var newLength []byte

	// Encrypt the stream first: its new length replaces the Length value,
	// which precedes the stream data.
	for i, tok := range tokens {
		if tok.kind != tokStream {
			continue
		}
		encrypt, err := streamEncrypted(enc, id, object, tokens, top)
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", id, err)
		}
		if !encrypt {
			continue
		}
		encrypted, err := enc.Encrypt(ptr, object[tok.start:tok.end])
		if err != nil {
			return nil, fmt.Errorf("object %d: encrypting stream: %w", id, err)
		}
		newLength = []byte(strconv.Itoa(len(encrypted)))
		tokens[i].value = encrypted
	}

	for i, tok := range tokens {
		switch {
		case i == lengthToken && newLength != nil:
			out = append(out, newLength...)
		case tok.kind == tokStream && tok.value != nil: // encrypted stream data
			out = append(out, tok.value...)
		case tok.kind == tokString && (!isSignature || tok.depth != 1 || tok.key != "Contents"):
			encrypted, err := enc.Encrypt(ptr, tok.value)
			if err != nil {
				return nil, fmt.Errorf("object %d: encrypting string: %w", id, err)
			}
			out = append(out, '<')
			out = append(out, strings.ToUpper(hex.EncodeToString(encrypted))...)
			out = append(out, '>')
		default:
			out = append(out, object[tok.start:tok.end]...)
		}
	}
	return out, nil
}

// streamEncrypted reports whether the stream of object id is encrypted with
// the method of the document's default crypt filter, deciding as the reader
// does (ISO 32000-2, 7.6.5 and 7.6.7). Not encrypted are the metadata stream
// of the catalog if the encryption dictionary sets /EncryptMetadata false, and
// a stream whose first filter is /Crypt with no /Name, the /Identity crypt
// filter or a crypt filter without a method. A stream naming a crypt filter
// with another method than the default one is an error: the security handler
// only encrypts with the default method.
func streamEncrypted(enc objectEncrypter, id uint32, src []byte, tokens []objToken, top map[string]topValue) (bool, error) {
	if typ, ok := top["Type"]; ok && typ.kind == tokName && string(typ.value) == "Metadata" && !enc.EncryptsMetadata() {
		if id == enc.Trailer().Key("Root").Key("Metadata").GetPtr().GetID() {
			return false, nil
		}
	}

	filter, ok := top["Filter"]
	if !ok {
		return true, nil
	}
	if filter.kind == tokArrayOpen {
		filter = firstElement(tokens, filter.index)
	}
	if filter.index >= 0 && isReferencePart(src, tokens[filter.index]) {
		return false, fmt.Errorf("indirect stream Filter is not supported")
	}
	if filter.kind != tokName || string(filter.value) != "Crypt" {
		return true, nil
	}

	name := ""
	if parms, ok := top["DecodeParms"]; ok {
		if parms.kind == tokArrayOpen {
			parms = firstElement(tokens, parms.index)
		}
		if parms.index >= 0 && isReferencePart(src, tokens[parms.index]) {
			return false, fmt.Errorf("indirect DecodeParms of a Crypt filter is not supported")
		}
		if parms.kind == tokDictOpen {
			name = dictName(tokens, parms.index, "Name")
		}
	}
	if name == "" || name == "Identity" {
		return false, nil
	}

	encrypt := enc.Trailer().Key("Encrypt")
	filters := encrypt.Key("CF")
	if filters.Key(name).Kind() != pdf.Dict {
		return false, fmt.Errorf("undefined crypt filter %s", name)
	}
	switch method := cryptFilterMethod(filters, name); method {
	case "None":
		return false, nil
	case cryptFilterMethod(filters, encrypt.Key("StmF").Name()):
		return true, nil
	default:
		return false, fmt.Errorf("crypt filter %s uses method %s, only the method of the default crypt filter is supported", name, method)
	}
}

// cryptFilterMethod returns the method (/CFM) of the named crypt filter: None
// if it has none, Identity for the Identity filter.
func cryptFilterMethod(filters pdf.Value, name string) string {
	if name == "" || name == "Identity" {
		return "Identity"
	}
	method := filters.Key(name).Key("CFM")
	if method.Kind() != pdf.Name {
		return "None"
	}
	return method.Name()
}

// firstElement returns the first token of the first element of the array
// opened by tokens[open], with index -1 if the array is empty.
func firstElement(tokens []objToken, open int) topValue {
	for i := open + 1; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok.kind == tokOther && isWhitespaceToken(tok):
		case tok.kind == tokArrayClose:
			return topValue{index: -1}
		default:
			return topValue{kind: tok.kind, value: tok.value, index: i}
		}
	}
	return topValue{index: -1}
}

// dictName returns the name value of key in the dictionary opened by
// tokens[open], or "" if it has none.
func dictName(tokens []objToken, open int, key string) string {
	depth := tokens[open].depth + 1
	for _, tok := range tokens[open+1:] {
		if tok.depth == depth && tok.kind == tokDictClose {
			break
		}
		if tok.depth == depth && tok.key == key && tok.kind == tokName {
			return string(tok.value)
		}
	}
	return ""
}

type topValue struct {
	kind  objTokenKind
	value []byte
	index int
}

// topLevelValues returns the first token of every value in the top-level dictionary.
func topLevelValues(tokens []objToken) map[string]topValue {
	values := make(map[string]topValue)
	for i, tok := range tokens {
		if tok.depth != 1 || tok.key == "" || tok.kind == tokOther && isWhitespaceToken(tok) {
			continue
		}
		if _, seen := values[tok.key]; !seen {
			values[tok.key] = topValue{kind: tok.kind, value: tok.value, index: i}
		}
	}
	return values
}

func isWhitespaceToken(tok objToken) bool {
	return tok.value != nil && len(bytes.TrimLeft(tok.value, "\x00\t\n\f\r ")) == 0
}

// tokenizeObject splits the body of an indirect object into tokens. It
// understands enough PDF syntax to find strings and stream data.
func tokenizeObject(src []byte) ([]objToken, error) {
	type container struct {
		dict      bool
		expectKey bool
		key       string
	}
	var (
		tokens []objToken
		stack  []container
		depth  int // number of open dictionaries
	)

	addToken := func(tok objToken) {
		tok.depth = depth
		if n := len(stack); n > 0 && stack[n-1].dict && tok.kind != tokDictClose && (tok.kind != tokOther || !isWhitespaceToken(tok)) {
			top := &stack[n-1]
			switch {
			case top.expectKey && tok.kind == tokName:
				top.key = string(tok.value)
				top.expectKey = false
			case !top.expectKey:
				tok.key = top.key
				// A value is complete unless it opens a container or is the
				// first part of a reference ("3 0 R").
				if tok.kind != tokDictOpen && tok.kind != tokArrayOpen && !isReferencePart(src, tok) {
					top.expectKey = true
				}
			}
		} else if n > 0 && !stack[n-1].dict {
			// Array elements inherit the key of the enclosing dictionary value.
			tok.key = stack[n-1].key
		}
		tokens = append(tokens, tok)
	}

	closeContainer := func() {
		stack = stack[:len(stack)-1]
		if n := len(stack); n > 0 && stack[n-1].dict {
			stack[n-1].expectKey = true
		}
	}

	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case isPDFWhitespace(c):
			j := i
			for j < len(src) && isPDFWhitespace(src[j]) {
				j++
			}
			addToken(objToken{kind: tokOther, start: i, end: j, value: src[i:j]})
			i = j
		case c == '%':
			j := i
			for j < len(src) && src[j] != '\n' && src[j] != '\r' {
				j++
			}
			tokens = append(tokens, objToken{kind: tokOther, start: i, end: j, depth: depth, value: []byte{' '}})
			i = j
		case c == '/':
			j := i + 1
			for j < len(src) && !isPDFWhitespace(src[j]) && !isPDFDelimiter(src[j]) {
				j++
			}
			addToken(objToken{kind: tokName, start: i, end: j, value: src[i+1 : j]})
			i = j
		case c == '(':
			value, end, err := readLiteralString(src, i)
			if err != nil {
				return nil, err
			}
			addToken(objToken{kind: tokString, start: i, end: end, value: value})
			i = end
		case c == '<' && i+1 < len(src) && src[i+1] == '<':
			addToken(objToken{kind: tokDictOpen, start: i, end: i + 2})
			key := ""
			if n := len(tokens); n > 0 {
				key = tokens[n-1].key
			}
			stack = append(stack, container{dict: true, expectKey: true, key: key})
			depth++
			i += 2
		case c == '<':
			value, end, err := readHexString(src, i)
			if err != nil {
				return nil, err
			}
			addToken(objToken{kind: tokString, start: i, end: end, value: value})
			i = end
		case c == '>' && i+1 < len(src) && src[i+1] == '>':
			if len(stack) == 0 || !stack[len(stack)-1].dict {
				return nil, fmt.Errorf("unexpected '>>' at offset %d", i)
			}
			addToken(objToken{kind: tokDictClose, start: i, end: i + 2})
			depth--
			closeContainer()
			i += 2
			if depth == 0 && len(stack) == 0 {
				end, stream, err := readStream(src, i, tokens)
				if err != nil {
					return nil, err
				}
				if stream != nil {
					tokens = append(tokens, objToken{kind: tokOther, start: i, end: stream.start})
					tokens = append(tokens, *stream)
					tokens = append(tokens, objToken{kind: tokOther, start: stream.end, end: end})
					i = end
				}
			}
		case c == '[':
			addToken(objToken{kind: tokArrayOpen, start: i, end: i + 1})
			key := tokens[len(tokens)-1].key
			stack = append(stack, container{key: key})
			i++
		case c == ']':
			if len(stack) == 0 || stack[len(stack)-1].dict {
				return nil, fmt.Errorf("unexpected ']' at offset %d", i)
			}
			addToken(objToken{kind: tokArrayClose, start: i, end: i + 1})
			closeContainer()
			i++
		default:
			j := i
			for j < len(src) && !isPDFWhitespace(src[j]) && !isPDFDelimiter(src[j]) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected %q at offset %d", c, i)
			}
			addToken(objToken{kind: tokOther, start: i, end: j})
			i = j
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unterminated dictionary or array")
	}
	return tokens, nil
}

// isReferencePart reports whether tok is the object or generation number of
// an indirect reference, such as the "3" or "0" in "3 0 R".
func isReferencePart(src []byte, tok objToken) bool {
	if tok.kind != tokOther {
		return false
	}
	if _, err := strconv.Atoi(string(src[tok.start:tok.end])); err != nil {
		return false
	}
	rest := bytes.TrimLeft(src[tok.end:], "\x00\t\n\f\r ")
	// If tok was the object number the generation number follows; skip it and
	// expect "R".
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j > 0 {
		rest = bytes.TrimLeft(rest[j:], "\x00\t\n\f\r ")
	}
	return len(rest) > 0 && rest[0] == 'R' && (len(rest) == 1 || isPDFWhitespace(rest[1]) || isPDFDelimiter(rest[1]))
}

// readStream reads stream data following the top-level dictionary that ends
// at offset i. It returns a nil token if no stream follows.
func readStream(src []byte, i int, tokens []objToken) (int, *objToken, error) {
	j := i
	for j < len(src) && isPDFWhitespace(src[j]) {
		j++
	}
	if !bytes.HasPrefix(src[j:], []byte("stream")) {
		return i, nil, nil
	}
	j += len("stream")
	switch {
	case bytes.HasPrefix(src[j:], []byte("\r\n")):
		j += 2
	case j < len(src) && src[j] == '\n':
		j++
	default:
		return 0, nil, fmt.Errorf("stream keyword not followed by an end-of-line marker")
	}

	// The same lookup as in encryptObject, which replaces this value.
	length := -1
	if v, ok := topLevelValues(tokens)["Length"]; ok {
		tok := tokens[v.index]
		if isReferencePart(src, tok) {
			return 0, nil, fmt.Errorf("indirect stream Length is not supported")
		}
		n, err := strconv.Atoi(string(src[tok.start:tok.end]))
		if err != nil {
			return 0, nil, fmt.Errorf("invalid stream Length: %w", err)
		}
		length = n
	}
	// Compare with the remaining bytes: j+length overflows for a huge Length.
	if length < 0 || length > len(src)-j {
		return 0, nil, fmt.Errorf("stream Length missing or beyond the object")
	}

	stream := &objToken{kind: tokStream, start: j, end: j + length}
	rest := src[j+length:]
	trimmed := bytes.TrimLeft(rest, "\r\n")
	if !bytes.HasPrefix(trimmed, []byte("endstream")) {
		return 0, nil, fmt.Errorf("endstream not found after %d bytes of stream data", length)
	}
	end := len(src) - len(trimmed) + len("endstream")
	return end, stream, nil
}

func readLiteralString(src []byte, start int) ([]byte, int, error) {
	var out []byte
	nesting := 0
	for i := start + 1; i < len(src); i++ {
		c := src[i]
		switch c {
		case '(':
			nesting++
			out = append(out, c)
		case ')':
			if nesting == 0 {
				return out, i + 1, nil
			}
			nesting--
			out = append(out, c)
		case '\r':
			// An end-of-line marker in a literal string is read as \n.
			if i+1 < len(src) && src[i+1] == '\n' {
				i++
			}
			out = append(out, '\n')
		case '\\':
			i++
			if i >= len(src) {
				return nil, 0, fmt.Errorf("unterminated literal string")
			}
			switch e := src[i]; e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\r':
				if i+1 < len(src) && src[i+1] == '\n' {
					i++
				}
			case '\n':
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for n := 1; n < 3 && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '7'; n++ {
						i++
						v = v*8 + int(src[i]-'0')
					}
					out = append(out, byte(v))
				} else {
					out = append(out, e) // \( \) \\ and unknown escapes
				}
			}
		default:
			out = append(out, c)
		}
	}
	return nil, 0, fmt.Errorf("unterminated literal string")
}

func readHexString(src []byte, start int) ([]byte, int, error) {
	var digits []byte
	for i := start + 1; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '>':
			if len(digits)%2 == 1 {
				digits = append(digits, '0')
			}
			value, err := hex.DecodeString(string(digits))
			if err != nil {
				return nil, 0, fmt.Errorf("invalid hexadecimal string: %w", err)
			}
			return value, i + 1, nil
		case isPDFWhitespace(c):
		default:
			digits = append(digits, c)
		}
	}
	return nil, 0, fmt.Errorf("unterminated hexadecimal string")
}

func isPDFWhitespace(c byte) bool {
	switch c {
	case '\x00', '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

func isPDFDelimiter(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}
