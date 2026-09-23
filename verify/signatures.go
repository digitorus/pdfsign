package verify

import (
	"bytes"
	"io"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

const (
	// removedSignature is the validation error recorded on a signature that
	// an earlier revision of the document held in its field tree or catalog
	// and the current field tree does not reach.
	removedSignature = "signature is not reachable from the current /AcroForm /Fields: an update removed or repointed its field after signing"

	// permsOnlySignature is the validation error recorded on a signature the
	// current catalog /Perms names as the certification signature while the
	// current field tree does not hold it.
	permsOnlySignature = "the catalog /Perms names a certification signature that the current /AcroForm /Fields does not hold"
)

// VerifySignatures verifies every signature the document holds and returns
// the signers of the signatures it could process, in the order found, with
// the number of signature dictionaries found, processed or not. A document
// without /AcroForm /SigFlags declares no signatures (ISO 32000-1 Table 218)
// and none are looked for.
//
// The signatures are the ones the current field tree reaches, then the one
// the current catalog /Perms /DocMDP names if the tree does not hold it, then
// those the field tree or catalog of an earlier revision of the file held
// that the current tree no longer does. An incremental update can drop a
// signed field from /Fields, or point it at another signature, without
// disturbing any signed bytes; a certification signature removed that way
// would otherwise never be verified and its DocMDP permissions never
// enforced, and an approval signature would be lost without a word. No
// permitted change removes a signed field, so such a signature is verified
// with a validation error saying so ahead of whatever else its verification
// finds, and is not reported as valid.
//
// Earlier revisions end at the %%EOF markers of the file, and only those that
// wrote a signature dictionary are read (see revisionEnds), through the reader
// a signature's verification opens where its /ByteRange covers the revision.
func VerifySignatures(rdr *pdf.Reader, file io.ReaderAt, fileSize int64, options *VerifyOptions) (signers []*Signer, found int) {
	root := rdr.Trailer().Key("Root")
	if root.Key("AcroForm").Key("SigFlags").IsNull() {
		return nil, 0
	}

	var set signatureSet
	set.addFields(root, fromFields)
	set.addPerms(root, fromPerms)

	// The earlier revisions that may hold a signature, by the end of their
	// %%EOF marker. One that a verified signature's /ByteRange covers is read
	// from the reader its verification opens; the rest are read once every
	// signature found so far has been verified.
	pending := make(map[int64]bool)
	for _, end := range revisionEnds(file, fileSize) {
		pending[end] = true
	}
	next := func() int64 {
		var end int64
		for e := range pending {
			if end == 0 || e < end {
				end = e
			}
		}
		delete(pending, end)
		return end
	}

	for i := 0; i < len(set.found) || len(pending) > 0; {
		if i == len(set.found) {
			set.addRevision(file, next(), options.Password)
			continue
		}
		sig := set.found[i]
		i++
		signer, revision, err := verifyDocumentSignature(sig.dict, rdr, file, fileSize, options)
		if end, ok := signedRangeEnd(sig.dict, fileSize); revision != nil && ok && end < fileSize {
			delete(pending, markerEnd(file, end))
			signedRoot := revision.Trailer().Key("Root")
			set.addFields(signedRoot, fromRevision)
			set.addPerms(signedRoot, fromRevision)
		}
		if err != nil {
			// The signature could not be processed; nothing to report.
			continue
		}
		switch sig.source {
		case fromPerms:
			signer.ValidationErrors = append([]error{&ValidationError{Msg: permsOnlySignature}}, signer.ValidationErrors...)
			signer.ValidSignature = false
		case fromRevision:
			signer.ValidationErrors = append([]error{&ValidationError{Msg: removedSignature}}, signer.ValidationErrors...)
			signer.ValidSignature = false
		}
		signers = append(signers, signer)
	}
	return signers, len(set.found)
}

// signatureSource says where a signature dictionary was found.
type signatureSource int

const (
	fromFields   signatureSource = iota // the current field tree
	fromPerms                           // the current catalog /Perms, not the field tree
	fromRevision                        // an earlier revision, not the current document
)

// documentSignature is a signature dictionary found in the document.
type documentSignature struct {
	dict   pdf.Value
	source signatureSource
}

// signatureSet collects the signature dictionaries a document holds. A
// signature is identified by its bytes: the same one may sit under different
// object numbers in different revisions, or be written directly into its
// field, and one found again that way is not a further signature.
type signatureSet struct {
	seen  map[string]bool
	found []documentSignature
}

// add records v when it is a signature dictionary. The current field tree is
// recorded field by field, even where fields share one signature: each signed
// field's value is verified, as it always was. From any other source only a
// signature not seen so far is recorded.
func (s *signatureSet) add(v pdf.Value, source signatureSource) {
	if !acroform.IsSignatureDictionary(v) {
		return
	}
	contents := v.Key("Contents").RawString()
	if source != fromFields && s.seen[contents] {
		return
	}
	if s.seen == nil {
		s.seen = make(map[string]bool)
	}
	s.seen[contents] = true
	s.found = append(s.found, documentSignature{dict: v, source: source})
}

// addFields adds the signatures the field tree below the catalog root holds,
// in document order.
func (s *signatureSet) addFields(root pdf.Value, source signatureSource) {
	acroform.SignatureFields(root, func(field pdf.Value) bool {
		s.add(field.Key("V"), source)
		return true
	})
}

// addPerms adds the certification signature the catalog's /Perms /DocMDP
// entry names (ISO 32000-1 12.8.2.2), a signed field of the document whether
// or not the field tree still reaches it.
func (s *signatureSet) addPerms(root pdf.Value, source signatureSource) {
	s.add(root.Key("Perms").Key("DocMDP"), source)
}

// addRevision adds the signatures the revision of the file ending at end
// holds. A section that does not read as a document, such as one ending at
// a marker inside a stream or the first-page section of a linearized file,
// holds nothing.
func (s *signatureSet) addRevision(file io.ReaderAt, end int64, password string) {
	revision, err := pdf.NewReaderEncrypted(io.NewSectionReader(file, 0, end), end, passwordFunc(password))
	if err != nil {
		return
	}
	root := revision.Trailer().Key("Root")
	s.addFields(root, fromRevision)
	s.addPerms(root, fromRevision)
}

// markerEnd returns the offset just past the %%EOF marker of the revision
// ending at end: the same offset less the line end that follows the marker,
// which a signature's /ByteRange may or may not cover.
func markerEnd(file io.ReaderAt, end int64) int64 {
	var tail [2]byte
	from := max(end-int64(len(tail)), 0)
	n, _ := file.ReadAt(tail[:end-from], from)
	for n > 0 && (tail[n-1] == '\r' || tail[n-1] == '\n') {
		n--
		end--
	}
	return end
}

// revisionEnds returns the end of every earlier revision of the file that may
// hold a signature: the offset just past its %%EOF marker (ISO 32000-1 7.5.5
// and 7.5.6), without the line end that follows it. Only a revision that wrote a
// signature dictionary can hold a signature the later revisions dropped: the
// dictionary lies inside its own /ByteRange, as a plain object of the
// revision that signed, so a revision whose bytes hold no /ByteRange key is
// left out.
func revisionEnds(file io.ReaderAt, fileSize int64) []int64 {
	var (
		marker = []byte("%%EOF")
		token  = []byte("/ByteRange")
	)
	var ends []int64
	buf := make([]byte, 1<<16)
	// Reads overlap by one byte less than the longer pattern, so a pattern
	// across two reads is found in the second; a marker found before found
	// was reported by the read before.
	overlap := len(token) - 1
	var found int64
	signing := false
	for offset := int64(0); offset < fileSize; offset += int64(len(buf) - overlap) {
		n, err := file.ReadAt(buf, offset)
		chunk := buf[:n]
		for i := 0; i < len(chunk); {
			m := bytes.Index(chunk[i:], marker)
			t := bytes.Index(chunk[i:], token)
			if m < 0 && t < 0 {
				break
			}
			if t >= 0 && (m < 0 || t < m) {
				signing = true
				i += t + len(token)
				continue
			}
			at := offset + int64(i+m)
			i += m + len(marker)
			if at < found {
				continue
			}
			if end := offset + int64(i); signing && markerEnd(file, fileSize) > end {
				ends = append(ends, end)
			}
			signing = false
		}
		if err != nil || n < len(buf) {
			break
		}
		found = offset + int64(n) - int64(len(marker)) + 1
	}
	return ends
}
