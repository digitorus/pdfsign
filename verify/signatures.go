package verify

import (
	"io"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
)

// unreachableSignature is the validation error recorded on a signature the
// current field tree does not reach.
const unreachableSignature = "signature is not reachable from the current /AcroForm /Fields: its field was removed or repointed after signing"

// VerifySignatures verifies every signature the document holds and returns
// the signers of the signatures it could process, in the order found, with
// the number of signature dictionaries found, processed or not.
//
// The signatures are the ones the current /AcroForm field tree reaches, the
// one the current catalog /Perms /DocMDP names, and then any that the field
// tree or catalog of a signed revision reached but the current tree no
// longer does. An incremental update can drop a field from /Fields, or point
// it at another signature, without disturbing any signed bytes; a
// certification signature removed that way would otherwise never be verified
// and its DocMDP permissions never enforced. Every signature verified opens
// the revision its /ByteRange covers (see signedSignatureDictionary), and the
// signatures that revision held are verified in turn. No permitted change
// removes a signed field, so a signature the current tree does not reach is
// verified with a validation error saying so.
func VerifySignatures(rdr *pdf.Reader, file io.ReaderAt, fileSize int64, options *VerifyOptions) (signers []*Signer, found int) {
	set := signatureSet{seen: make(map[string]bool)}
	root := rdr.Trailer().Key("Root")
	set.addFields(root, true)
	reachable := len(set.found)
	set.addPerms(root)

	for i := 0; i < len(set.found); i++ {
		signer, revision, err := verifyDocumentSignature(set.found[i], file, fileSize, options)
		if revision != nil {
			signedRoot := revision.Trailer().Key("Root")
			set.addFields(signedRoot, false)
			set.addPerms(signedRoot)
		}
		if err != nil {
			// The signature could not be processed; nothing to report.
			continue
		}
		if i >= reachable {
			signer.ValidationErrors = append([]error{&ValidationError{Msg: unreachableSignature}}, signer.ValidationErrors...)
		}
		signers = append(signers, signer)
	}
	return signers, len(set.found)
}

// signatureSet collects the signature dictionaries a document holds. A
// signature is identified by its bytes: the same one may sit under different
// object numbers in different revisions, or be written directly into its
// field, and one found again that way is not a further signature.
type signatureSet struct {
	seen  map[string]bool
	found []pdf.Value
}

// add records v when it is a signature dictionary. With every set, it is
// recorded even when its signature bytes were found before; otherwise only a
// signature not seen so far is.
func (s *signatureSet) add(v pdf.Value, every bool) {
	if !isSignatureDictionary(v) {
		return
	}
	contents := v.Key("Contents").RawString()
	if !every && s.seen[contents] {
		return
	}
	s.seen[contents] = true
	s.found = append(s.found, v)
}

// addFields adds the signatures the field tree below the catalog root holds,
// in document order. The current document's tree is added with every set:
// each signed field's value is verified, as it always was, so a document
// whose fields share one signature reports it once per field.
func (s *signatureSet) addFields(root pdf.Value, every bool) {
	acroform.SignatureFields(root, func(field pdf.Value) bool {
		s.add(field.Key("V"), every)
		return true
	})
}

// addPerms adds the certification signature the catalog's /Perms /DocMDP
// entry names (ISO 32000-1 12.8.2.2), a signed field of the document whether
// or not the field tree still reaches it, unless it was found already.
func (s *signatureSet) addPerms(root pdf.Value) {
	s.add(root.Key("Perms").Key("DocMDP"), false)
}

// isSignatureDictionary reports whether v is a signature dictionary (ISO
// 32000-1 Table 252): one typed as a signature or a document timestamp, or
// one that names its handler and carries signature bytes.
func isSignatureDictionary(v pdf.Value) bool {
	if v.Kind() != pdf.Dict {
		return false
	}
	switch v.Key("Type").Name() {
	case "Sig", "DocTimeStamp":
		return true
	}
	return !v.Key("Filter").IsNull() && !v.Key("Contents").IsNull()
}
