package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// VerifySignature processes a single digital signature found in the PDF.
//
// VerifySignatures verifies every signature a document holds, including one
// that an incremental update removed from the field tree; this verifies the
// one given.
func VerifySignature(v pdf.Value, file io.ReaderAt, fileSize int64, options *VerifyOptions) (*Signer, error) {
	signer, _, err := verifyDocumentSignature(v, nil, file, fileSize, options)
	return signer, err
}

// verifyDocumentSignature verifies the signature dictionary v. current reads
// the whole document, or is nil to have it opened when needed. The reader
// returned is over the revision the signature covers, when that could be
// read, so a caller can find the signatures that revision held; it is set
// whether or not verification got further.
func verifyDocumentSignature(v pdf.Value, current *pdf.Reader, file io.ReaderAt, fileSize int64, options *VerifyOptions) (*Signer, *pdf.Reader, error) {
	signer := NewSigner()

	// Validate the signature dictionary as it was signed, not as the current
	// cross-reference table presents it; see signedSignatureDictionary.
	v, revision, ok := signedSignatureDictionary(v, file, fileSize, signer, options.Password)
	if !ok {
		return signer, revision, nil
	}

	signer.Name = v.Key("Name").Text()
	signer.Reason = v.Key("Reason").Text()
	signer.Location = v.Key("Location").Text()
	signer.ContactInfo = v.Key("ContactInfo").Text()

	// Check for DocMDP and incremental updates
	if err := checkDocMDP(v, revision, current, file, fileSize, signer, options.Password); err != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("DocMDP validation failed: %v", err)})
		return signer, revision, nil
	}

	// Parse signature time if available from the signature object
	sigTime := v.Key("M")
	if !sigTime.IsNull() {
		if t, err := parseDate(sigTime.Text()); err == nil {
			signer.SignatureTime = &t
		}
	}

	// Parse PKCS#7 signature
	rawSignature := []byte(v.Key("Contents").RawString())
	p7, err := pkcs7.Parse(rawSignature)
	if err != nil {
		return signer, revision, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	isDocTimeStamp := (v.Key("SubFilter").Name() == "ETSI.RFC3161")

	if isDocTimeStamp {
		// DocTimeStamp: p7.Content contains the TSTInfo (embedded).
		// We verify the PDF bytes match the TSTInfo MessageImprint.
		pdfBytes, err := readByteRange(v, file)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to read ByteRange: %v", err)})
			return signer, revision, nil
		}

		// Parse TSTInfo to check MessageImprint.
		// We parse the original token because timestamp.Parse expects ContentInfo,
		// whereas p7.Content is the inner TSTInfo.
		ts, err := timestamp.Parse(rawSignature)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to parse TSTInfo: %v", err)})
			return signer, revision, nil
		}
		signer.TimeStamp = ts

		// Verify hash of PDF bytes vs MessageImprint
		h := ts.HashAlgorithm.New()
		h.Write(pdfBytes)
		if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: "timestamp hash does not match"})
			return signer, revision, nil
		}

		// Verify reference to the previous signature (if available).
		// For a DocTimeStamp, if there are previous signatures, the ByteRange
		// covers them. So the hash check above implicitly validates the integrity
		// of the previous state.

		// Verify the TSTInfo signature (standard verification on embedded content)
		// We skip processTimestamp as the timestamp IS the content, not an attribute.
		err = verifySignature(p7, signer)
		if err != nil {
			// Specific error for DocTimeStamp
			signer.ValidationErrors = append(signer.ValidationErrors, &InvalidSignatureError{Msg: fmt.Sprintf("Failed to verify timestamp signature: %v", err)})
			return signer, revision, nil
		}

	} else {
		// Standard Detached Signature
		// Process byte range uses the PDF content as the signed data
		err = processByteRange(v, file, p7)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process ByteRange: %v", err)})
			return signer, revision, nil
		}

		// Process timestamp if present (as an attribute)
		err = processTimestamp(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process timestamp: %v", err)})
			return signer, revision, nil
		}

		// Verify the digital signature
		err = verifySignature(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &InvalidSignatureError{Msg: fmt.Sprintf("Failed to verify signature: %v", err)})
			return signer, revision, nil
		}
	}

	// Process certificate chains and revocation
	var revInfo revocation.InfoArchival
	_ = p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, &revInfo)

	certError := buildCertificateChainsWithOptions(p7, signer, revInfo, options, isDocTimeStamp)
	if certError != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, certError)
	}

	// Check algorithm constraints
	if algoErr := verifyAlgorithmAndKeySize(signer, p7, options); algoErr != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, &PolicyError{Msg: fmt.Sprintf("Algorithm verification failed: %v", algoErr)})
		return signer, revision, nil
	}

	return signer, revision, nil
}

func verifyAlgorithmAndKeySize(signer *Signer, p7 *pkcs7.PKCS7, options *VerifyOptions) error {
	if len(signer.Certificates) == 0 {
		return nil
	}

	// Identify the leaf signer
	// We try to match the signer info from p7
	var leafCert *x509.Certificate
	if len(p7.Signers) > 0 {
		signerInfo := p7.Signers[0]
		for _, cert := range p7.Certificates {
			// Compare Serial Number
			if cert.SerialNumber.Cmp(signerInfo.IssuerAndSerialNumber.SerialNumber) == 0 {
				// Compare Issuer (Raw Bytes)
				// signerInfo.IssuerAndSerialNumber.IssuerName is asn1.RawValue
				if bytes.Equal(cert.RawIssuer, signerInfo.IssuerAndSerialNumber.IssuerName.FullBytes) {
					leafCert = cert
					break
				}
			}
		}
	}
	// Fallback if not found (e.g. strict matching fail), assume first in list if single
	if leafCert == nil && len(p7.Certificates) > 0 {
		leafCert = p7.Certificates[0]
	}

	if options.ValidateFullChain {
		// Verify all certificates
		for _, certWrapper := range signer.Certificates {
			isLeaf := (certWrapper.Certificate == leafCert)
			if err := verifyCertificateAlgorithmAndKeySize(certWrapper.Certificate, options, isLeaf); err != nil {
				return err
			}
		}
	} else {
		// Only verify the leaf
		if leafCert != nil {
			if err := verifyCertificateAlgorithmAndKeySize(leafCert, options, true); err != nil {
				return err
			}
		}
	}

	return nil
}

func verifyCertificateAlgorithmAndKeySize(cert *x509.Certificate, options *VerifyOptions, isLeaf bool) error {
	if cert == nil {
		return nil
	}

	if len(options.AllowedAlgorithms) > 0 {
		allowed := false
		for _, algo := range options.AllowedAlgorithms {
			if cert.PublicKeyAlgorithm == algo {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("public key algorithm %s is not allowed (isLeaf: %v)", cert.PublicKeyAlgorithm, isLeaf)
		}
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if options.MinRSAKeySize > 0 && pub.N.BitLen() < options.MinRSAKeySize {
			return fmt.Errorf("RSA key size %d is less than minimum %d (isLeaf: %v)", pub.N.BitLen(), options.MinRSAKeySize, isLeaf)
		}
	case *ecdsa.PublicKey:
		if options.MinECDSAKeySize > 0 && pub.Params().BitSize < options.MinECDSAKeySize {
			return fmt.Errorf("ECDSA key size %d is less than minimum %d (isLeaf: %v)", pub.Params().BitSize, options.MinECDSAKeySize, isLeaf)
		}
	}
	return nil
}

// processByteRange processes the byte range for signature verification.
func processByteRange(v pdf.Value, file io.ReaderAt, p7 *pkcs7.PKCS7) error {
	content, err := readByteRange(v, file)
	if err != nil {
		return err
	}
	p7.Content = content
	return nil
}

// readByteRange reads the content defined by ByteRange.
func readByteRange(v pdf.Value, file io.ReaderAt) ([]byte, error) {
	var parts []io.Reader
	var totalSize int64

	br := v.Key("ByteRange")
	if br.Len()%2 != 0 {
		return nil, fmt.Errorf("invalid ByteRange length: %d", br.Len())
	}

	for i := 0; i < br.Len(); i += 2 {
		offset := br.Index(i).Int64()
		length := br.Index(i + 1).Int64()

		parts = append(parts, io.NewSectionReader(file, offset, length))
		totalSize += length
	}

	// Pre-allocate the content buffer
	content := make([]byte, totalSize)

	// Use MultiReader to treat the separate ranges as a single continuous stream
	reader := io.MultiReader(parts...)

	_, err := io.ReadFull(reader, content)
	if err != nil {
		return nil, fmt.Errorf("failed to read signed content: %v", err)
	}

	return content, nil
}

// processTimestamp processes timestamp information from the signature.
func processTimestamp(p7 *pkcs7.PKCS7, signer *Signer) error {
	for _, s := range p7.Signers {
		// Timestamp - RFC 3161 id-aa-timeStampToken
		for _, attr := range s.UnauthenticatedAttributes {
			if attr.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}) {
				ts, err := timestamp.Parse(attr.Value.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse timestamp: %v", err)
				}

				signer.TimeStamp = ts

				// Verify timestamp hash
				r := bytes.NewReader(s.EncryptedDigest)
				h := signer.TimeStamp.HashAlgorithm.New()
				b := make([]byte, h.Size())
				for {
					n, err := r.Read(b)
					if err == io.EOF {
						break
					}
					h.Write(b[:n])
				}

				if !bytes.Equal(h.Sum(nil), signer.TimeStamp.HashedMessage) {
					return fmt.Errorf("timestamp hash does not match")
				}
				break
			}
		}
	}
	return nil
}

// verifySignature verifies the digital signature.
func verifySignature(p7 *pkcs7.PKCS7, signer *Signer) error {
	// Directory of certificates, including OCSP
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}

	// Verify the digital signature of the pdf file.
	err := p7.VerifyWithChain(certPool)
	if err != nil {
		err = p7.Verify()
		if err == nil {
			signer.ValidSignature = true
			signer.TrustedIssuer = false
		} else {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	} else {
		signer.ValidSignature = true
		signer.TrustedIssuer = true
	}

	return nil
}

// signedRangeEnd returns the end of the byte range a signature covers, and
// false when the /ByteRange cannot describe a signed revision of this file.
func signedRangeEnd(v pdf.Value, fileSize int64) (int64, bool) {
	br := v.Key("ByteRange")
	if br.Len() < 4 {
		return 0, false
	}
	end := br.Index(2).Int64() + br.Index(3).Int64()
	if end <= 0 || end > fileSize {
		return 0, false
	}
	return end, true
}

// signedSignatureDictionary returns the signature dictionary as the revision
// its /ByteRange covers holds it, together with a reader over that revision.
//
// A signature dictionary lies inside its own byte range (ISO 32000-1 12.8.1:
// the range covers the whole file apart from the /Contents string), so the
// signed revision holds the authoritative copy. An incremental update can
// redefine the object the current cross-reference table points to, or point
// the field's /V at a copy, without disturbing the signed bytes; dropping the
// DocMDP transform or changing the reported signer that way must not pass. A
// current copy that differs in an entry validation depends on is recorded as
// a validation error, and the signed copy is used either way.
//
// When the signed revision cannot be read, the current copy is used with a
// warning and the returned reader is nil. ok is false when the dictionary is
// not part of the signed revision at all; nothing about it can be trusted
// then, and the validation error recorded is the verdict.
func signedSignatureDictionary(v pdf.Value, file io.ReaderAt, fileSize int64, signer *Signer, password string) (signed pdf.Value, revision *pdf.Reader, ok bool) {
	signedEnd, ok := signedRangeEnd(v, fileSize)
	if !ok {
		return v, nil, true
	}
	revision, err := pdf.NewReaderEncrypted(io.NewSectionReader(file, 0, signedEnd), signedEnd, passwordFunc(password))
	if err != nil {
		signer.Warnings = append(signer.Warnings, &Warning{
			Msg: "the revision this signature covers could not be read; the signature dictionary is taken from the current file, and changes after signing cannot be checked against a DocMDP transform it declares",
		})
		return v, nil, true
	}

	signed, found := findSignatureDictionary(revision, v)
	if !found {
		signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{
			Msg: "signature dictionary is not part of the revision its ByteRange covers",
		})
		return v, revision, false
	}
	if key := signatureDictionaryDifference(v, signed); key != "" {
		signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{
			Msg: fmt.Sprintf("signature dictionary was modified after signing: /%s differs from the signed revision", key),
		})
	}
	return signed, revision, true
}

// findSignatureDictionary looks the signature dictionary v up in the signed
// revision: under its own object number when that holds the same signature,
// or else, for a dictionary written directly into its field or a field that
// was pointed at a copy, through the field tree by its signature bytes.
func findSignatureDictionary(revision *pdf.Reader, v pdf.Value) (pdf.Value, bool) {
	if id := v.GetPtr().GetID(); id > 0 {
		if signed, err := revision.GetObject(id); err == nil && sameSignature(v, signed) {
			return signed, true
		}
	}

	var signed pdf.Value
	found := false
	acroform.SignatureFields(revision.Trailer().Key("Root"), func(field pdf.Value) bool {
		if w := field.Key("V"); sameSignature(v, w) {
			signed, found = w, true
			return false
		}
		return true
	})
	return signed, found
}

// sameSignature reports whether two signature dictionaries hold the same
// signature, by their signature bytes: the object number does not identify
// one, since either copy may be written directly into its container and then
// carries that container's pointer.
func sameSignature(a, b pdf.Value) bool {
	contents := a.Key("Contents").RawString()
	return contents != "" && b.Kind() == pdf.Dict && b.Key("Contents").RawString() == contents
}

// signatureDictionaryDifference returns the first entry that validation depends
// on whose value differs between the current and the signed copy of a
// signature dictionary, or "" when they agree.
func signatureDictionaryDifference(current, signed pdf.Value) string {
	for _, key := range []string{"Type", "Filter", "SubFilter", "ByteRange", "Contents", "Reference"} {
		if canonicalEntry(current, current.Key(key), 0) != canonicalEntry(signed, signed.Key(key), 0) {
			return key
		}
	}
	return ""
}

// canonical renders a value with dictionary keys sorted and indirect objects
// kept as references, so two copies compare by what they say. A DocMDP
// signature reference dictionary may carry /Data pointing at the catalog;
// resolving that would pull the whole document into the comparison, and the
// signed copy is read through the signed revision anyway, so a target
// redefined later cannot reach validation.
func canonical(v pdf.Value, depth int) string {
	if depth > 16 {
		return "..."
	}
	switch v.Kind() {
	case pdf.Bool:
		return strconv.FormatBool(v.Bool())
	case pdf.Integer:
		return strconv.FormatInt(v.Int64(), 10)
	case pdf.Real:
		return strconv.FormatFloat(v.Float64(), 'f', -1, 64)
	case pdf.String:
		return strconv.Quote(v.RawString())
	case pdf.Name:
		return "/" + v.Name()
	case pdf.Array:
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = canonicalEntry(v, v.Index(i), depth+1)
		}
		return "[" + strings.Join(parts, " ") + "]"
	case pdf.Dict:
		keys := v.Keys()
		parts := make([]string, len(keys))
		for i, key := range keys {
			parts[i] = "/" + key + " " + canonicalEntry(v, v.Key(key), depth+1)
		}
		return "<<" + strings.Join(parts, " ") + ">>"
	case pdf.Stream:
		keys := v.Keys()
		parts := make([]string, len(keys))
		for i, key := range keys {
			parts[i] = "/" + key + " " + canonicalEntry(v, v.Key(key), depth+1)
		}
		return "<<" + strings.Join(parts, " ") + ">>stream"
	}
	return "null"
}

// canonicalEntry renders an entry of container: as a reference when it is an
// indirect object (a direct entry carries its container's pointer), else in
// full.
func canonicalEntry(container, entry pdf.Value, depth int) string {
	if ptr := entry.GetPtr(); ptr != container.GetPtr() {
		return fmt.Sprintf("%d %d R", ptr.GetID(), ptr.GetGen())
	}
	return canonical(entry, depth)
}

// checkDocMDP verifies Document Modification Detection and Prevention permissions.
//
// ISO 32000-1 12.8.2.2: the certification signature is the one the document
// catalog's /Perms /DocMDP entry references. The DocMDP transform in the
// signature's /Reference states the permission level, but only that catalog
// entry makes a conforming reader apply it; a signature that carries the
// transform without being referenced from /Perms is an approval signature to
// every reader, so its permission level is not enforced here either. The
// catalog is read from the revision the signature covers, since an update
// appended later could otherwise remove the entry and switch enforcement off;
// when that revision cannot be read (revision is nil, which
// signedSignatureDictionary has warned about), the transform is enforced as
// declared.
//
// The incremental updates after the signed revision are then held against
// the permission level: every change they make has to be one the level
// permits (see checkPermittedChanges), which needs the signed revision; an
// update after a revision that cannot be read fails. current reads the whole
// document, or is nil to have it opened here.
func checkDocMDP(v pdf.Value, revision, current *pdf.Reader, file io.ReaderAt, fileSize int64, signer *Signer, password string) error {
	transform, ok := docMDPTransform(v.Key("Reference"))
	if !ok {
		return nil
	}

	signedEnd, ok := signedRangeEnd(v, fileSize)
	if !ok {
		return nil // Should fail elsewhere if ByteRange is bad
	}

	switch referenced, known := catalogReferencesDocMDP(v, revision); {
	case !known:
		// Enforced as declared.
	case !referenced:
		signer.Warnings = append(signer.Warnings, &Warning{
			Msg: "signature declares a DocMDP transform but the document catalog /Perms does not reference it; readers treat it as an approval signature and its permission level is not applied",
		})
		return nil
	}

	perms := 2 // Default
	params := transform.Key("TransformParams")
	if !params.IsNull() {
		p := params.Key("P")
		if !p.IsNull() {
			perms = int(p.Int64())
		}
	}

	if fileSize <= signedEnd {
		return nil
	}
	// An incremental update follows the signed revision.
	if revision == nil {
		return fmt.Errorf("incremental update found but the revision the signature covers could not be read, so the changes cannot be checked against P=%d", perms)
	}
	if current == nil {
		var err error
		if current, err = pdf.NewReaderEncrypted(file, fileSize, passwordFunc(password)); err != nil {
			return fmt.Errorf("incremental update found but the document could not be read to check the changes against P=%d: %w", perms, err)
		}
	}
	p := docMDPPermissions(perms)
	if err := checkPermittedChanges(revision, current, p); err != nil {
		return err
	}
	msg := "DocMDP P=%d: incremental update found; it adds validation data or document timestamps only"
	if p.formFilling {
		msg = "DocMDP P=%d: incremental update found; it holds permitted changes only"
	}
	signer.Warnings = append(signer.Warnings, &Warning{Msg: fmt.Sprintf(msg, perms)})
	return nil
}

// docMDPTransform returns the signature reference dictionary whose transform
// method is DocMDP, if the /Reference array carries one.
func docMDPTransform(refs pdf.Value) (pdf.Value, bool) {
	if refs.IsNull() || refs.Kind() != pdf.Array {
		return pdf.Value{}, false
	}
	for i := 0; i < refs.Len(); i++ {
		ref := refs.Index(i)
		if ref.Key("TransformMethod").Name() == "DocMDP" {
			return ref, true
		}
	}
	return pdf.Value{}, false
}

// catalogReferencesDocMDP reports whether the document catalog's /Perms /DocMDP
// entry of the signed revision is the signature dictionary v. known is false
// when the revision is not available.
func catalogReferencesDocMDP(v pdf.Value, revision *pdf.Reader) (referenced, known bool) {
	if revision == nil {
		return false, false
	}
	docMDP := revision.Trailer().Key("Root").Key("Perms").Key("DocMDP")
	if docMDP.IsNull() {
		return false, true
	}

	// Both are normally the same indirect object; either may instead be
	// written directly into its container.
	if id := v.GetPtr().GetID(); id > 0 && docMDP.GetPtr().GetID() == id {
		return true, true
	}
	return sameSignature(v, docMDP), true
}

// collectProtectedPageObjects walks the current page tree starting at node,
// adding to protected the object ID of every page and, where present as its
// own indirect object, each page's Contents and Resources. Resources not set
// directly on a leaf page are inherited from the nearest ancestor Pages node
// that has one, per ISO 32000-1 7.7.3.4. visited guards against cycles in a
// malformed or adversarial page tree.
func collectProtectedPageObjects(node, inheritedResources pdf.Value, protected map[uint32]bool, visited map[uint32]bool) {
	if node.IsNull() {
		return
	}
	if id := node.GetPtr().GetID(); id > 0 {
		if visited[id] {
			return
		}
		visited[id] = true
		protected[id] = true
	}

	resources := node.Key("Resources")
	if resources.IsNull() {
		resources = inheritedResources
	}

	if kids := node.Key("Kids"); kids.Kind() == pdf.Array {
		for i := 0; i < kids.Len(); i++ {
			collectProtectedPageObjects(kids.Index(i), resources, protected, visited)
		}
		return
	}

	// Leaf page.
	switch contents := node.Key("Contents"); contents.Kind() {
	case pdf.Array:
		for i := 0; i < contents.Len(); i++ {
			if id := contents.Index(i).GetPtr().GetID(); id > 0 {
				protected[id] = true
			}
		}
	default:
		if id := contents.GetPtr().GetID(); id > 0 {
			protected[id] = true
		}
	}

	if id := resources.GetPtr().GetID(); id > 0 {
		protected[id] = true
	}
	protectResourceEntries(resources, protected)
}

// protectResourceEntries adds the object ID of every resource directly
// referenced from a Resources dict's Font, XObject, ExtGState, Pattern,
// Shading, and Properties sub-dictionaries. A legitimate P=2/P=3 update
// adds new resources under new object IDs rather than rewriting an existing
// page's fonts, images, or other resources in place, so protecting these
// too doesn't risk false positives on legitimate updates.
func protectResourceEntries(resources pdf.Value, protected map[uint32]bool) {
	if resources.IsNull() {
		return
	}
	for _, category := range []string{"Font", "XObject", "ExtGState", "Pattern", "Shading", "Properties"} {
		sub := resources.Key(category)
		if sub.IsNull() || sub.Kind() != pdf.Dict {
			continue
		}
		for _, key := range sub.Keys() {
			if id := sub.Key(key).GetPtr().GetID(); id > 0 {
				protected[id] = true
			}
		}
	}
}
