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
// Earlier revisions are read at each %%EOF marker of the file; the revision a
// signature's /ByteRange covers, which its verification opens anyway, is read
// as well, for a file whose revisions are not laid out that way.
func VerifySignatures(rdr *pdf.Reader, file io.ReaderAt, fileSize int64, options *VerifyOptions) (signers []*Signer, found int) {
	root := rdr.Trailer().Key("Root")
	if root.Key("AcroForm").Key("SigFlags").IsNull() {
		return nil, 0
	}

	var set signatureSet
	set.addFields(root, fromFields)
	set.addPerms(root, fromPerms)
	set.addRevisions(file, fileSize, options.Password)

	for i := 0; i < len(set.found); i++ {
		sig := set.found[i]
		signer, revision, err := verifyDocumentSignature(sig.dict, file, fileSize, options)
		if end, ok := signedRangeEnd(sig.dict, fileSize); revision != nil && ok && end < fileSize {
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

// addRevisions adds the signatures every earlier revision of the file holds.
// A revision ends with its %%EOF marker (ISO 32000-1 7.5.5 and 7.5.6), so the
// document as it stood at each marker is read. A section that does not read
// as a document, such as a marker inside a stream or the first-page section
// of a linearized file, holds nothing.
func (s *signatureSet) addRevisions(file io.ReaderAt, fileSize int64, password string) {
	for _, end := range revisionEnds(file, fileSize) {
		revision, err := pdf.NewReaderEncrypted(io.NewSectionReader(file, 0, end), end, passwordFunc(password))
		if err != nil {
			continue
		}
		root := revision.Trailer().Key("Root")
		s.addFields(root, fromRevision)
		s.addPerms(root, fromRevision)
	}
}

// revisionEnds returns the end of every revision of the file but the last:
// the offset just past each %%EOF marker and the line end that follows it.
func revisionEnds(file io.ReaderAt, fileSize int64) []int64 {
	const marker = "%%EOF"
	var ends []int64
	buf := make([]byte, 1<<16)
	// Reads overlap by one byte less than the marker, so a marker across
	// two reads is found in the second and none is found twice.
	for offset := int64(0); offset < fileSize; offset += int64(len(buf) - len(marker) + 1) {
		n, err := file.ReadAt(buf, offset)
		chunk := buf[:n]
		for i := 0; ; {
			j := bytes.Index(chunk[i:], []byte(marker))
			if j < 0 {
				break
			}
			i += j + len(marker)
			for i < len(chunk) && (chunk[i] == '\r' || chunk[i] == '\n') {
				i++
			}
			if end := offset + int64(i); end < fileSize {
				ends = append(ends, end)
			}
		}
		if err != nil || n < len(buf) {
			break
		}
	}
	return ends
}
