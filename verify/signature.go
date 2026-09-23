package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// VerifySignature processes a single digital signature found in the PDF.
func VerifySignature(v pdf.Value, file io.ReaderAt, fileSize int64, options *VerifyOptions) (*Signer, error) {
	signer := NewSigner()
	signer.Name = v.Key("Name").Text()
	signer.Reason = v.Key("Reason").Text()
	signer.Location = v.Key("Location").Text()
	signer.ContactInfo = v.Key("ContactInfo").Text()

	// Check for DocMDP and incremental updates
	if err := checkDocMDP(v, file, fileSize, signer, options.Password); err != nil {
		signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("DocMDP validation failed: %v", err)})
		return signer, nil
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
		return signer, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	isDocTimeStamp := (v.Key("SubFilter").Name() == "ETSI.RFC3161")

	if isDocTimeStamp {
		// DocTimeStamp: p7.Content contains the TSTInfo (embedded).
		// We verify the PDF bytes match the TSTInfo MessageImprint.
		pdfBytes, err := readByteRange(v, file)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to read ByteRange: %v", err)})
			return signer, nil
		}

		// Parse TSTInfo to check MessageImprint.
		// We parse the original token because timestamp.Parse expects ContentInfo,
		// whereas p7.Content is the inner TSTInfo.
		ts, err := timestamp.Parse(rawSignature)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to parse TSTInfo: %v", err)})
			return signer, nil
		}
		signer.TimeStamp = ts

		// Verify hash of PDF bytes vs MessageImprint
		h := ts.HashAlgorithm.New()
		h.Write(pdfBytes)
		if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: "timestamp hash does not match"})
			return signer, nil
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
			return signer, nil
		}

	} else {
		// Standard Detached Signature
		// Process byte range uses the PDF content as the signed data
		err = processByteRange(v, file, p7)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process ByteRange: %v", err)})
			return signer, nil
		}

		// Process timestamp if present (as an attribute)
		err = processTimestamp(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &ValidationError{Msg: fmt.Sprintf("Failed to process timestamp: %v", err)})
			return signer, nil
		}

		// Verify the digital signature
		err = verifySignature(p7, signer)
		if err != nil {
			signer.ValidationErrors = append(signer.ValidationErrors, &InvalidSignatureError{Msg: fmt.Sprintf("Failed to verify signature: %v", err)})
			return signer, nil
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
		return signer, nil
	}

	return signer, nil
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
// when that revision cannot be read, the transform is enforced as declared.
func checkDocMDP(v pdf.Value, file io.ReaderAt, fileSize int64, signer *Signer, password string) error {
	transform, ok := docMDPTransform(v.Key("Reference"))
	if !ok {
		return nil
	}

	br := v.Key("ByteRange")
	if br.Len() < 4 {
		return nil // Should fail elsewhere if ByteRange is bad
	}

	// End of the signed range
	signedEnd := br.Index(2).Int64() + br.Index(3).Int64()
	if signedEnd <= 0 || signedEnd > fileSize {
		return nil
	}

	switch referenced, known := catalogReferencesDocMDP(v, io.NewSectionReader(file, 0, signedEnd), signedEnd, password); {
	case !known:
		signer.Warnings = append(signer.Warnings, &Warning{
			Msg: "the revision this signature covers could not be read to check the document catalog /Perms; the DocMDP transform is enforced as declared",
		})
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

	// Detect if there are modifications (bytes appended)
	if fileSize > signedEnd {
		// We have an incremental update

		// P=1: No changes permitted
		if perms == 1 {
			// Strictly invalid
			return fmt.Errorf("incremental update found but P=1 (NoChanges) permits none")
		}

		// P=2 (form filling) and P=3 (annotations) permit an
		// incremental update, but never one that rewrites a page's
		// own content stream or resources - legitimate form fills,
		// new signatures, and new annotations are always written as
		// new, additional objects. An update that also rewrites page
		// content in the same pass (hidden behind a permitted
		// change) is the PDF "Shadow Attack" pattern (Mainka et al.,
		// USENIX Security 2021); reject it rather than merely warn.
		if perms == 2 || perms == 3 {
			if err := checkIncrementalUpdateScope(file, fileSize, signedEnd, password); err != nil {
				return err
			}
			signer.Warnings = append(signer.Warnings, &Warning{
				Msg: fmt.Sprintf("DocMDP P=%d: incremental update found; page content/resources were not among the objects it rewrote", perms),
			})
		}
	}
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
// entry, as read from the given (signed) revision of the file, is the signature
// dictionary v. known is false when that revision could not be read.
func catalogReferencesDocMDP(v pdf.Value, revision io.ReaderAt, size int64, password string) (referenced, known bool) {
	rdr, err := pdf.NewReaderEncrypted(revision, size, passwordFunc(password))
	if err != nil {
		return false, false
	}
	docMDP := rdr.Trailer().Key("Root").Key("Perms").Key("DocMDP")
	if docMDP.IsNull() {
		return false, true
	}

	// Both are normally the same indirect object.
	if id := v.GetPtr().GetID(); id > 0 && docMDP.GetPtr().GetID() == id {
		return true, true
	}
	// Either may instead be written directly into its container and then
	// carries that container's pointer; the signature bytes identify the
	// dictionary in that case.
	contents := v.Key("Contents").RawString()
	return contents != "" && docMDP.Key("Contents").RawString() == contents, true
}

// objDefPattern matches a classic PDF indirect object definition header
// ("<id> <gen> obj"), capturing the object number.
var objDefPattern = regexp.MustCompile(`(?:^|[^0-9])([0-9]+)[ \t\r\n\f\x00]+[0-9]+[ \t\r\n\f\x00]+obj\b`)

// checkIncrementalUpdateScope returns an error if the incremental update
// appended after signedEnd redefines a page object, or a page's own
// /Contents or /Resources object, in the CURRENT (fully updated) document.
//
// Limitation: object definitions are located by scanning the update's raw
// bytes for classic "<id> <gen> obj" headers. An object written only inside
// a compressed object stream (used by some xref-stream-format incremental
// updates) has no such textual header and is not covered by this check.
func checkIncrementalUpdateScope(file io.ReaderAt, fileSize, signedEnd int64, password string) error {
	rdr, err := pdf.NewReaderEncrypted(file, fileSize, passwordFunc(password))
	if err != nil {
		return nil // Can't determine scope; structural checks elsewhere catch a broken file.
	}

	protected := make(map[uint32]bool)
	pagesRoot := rdr.Trailer().Key("Root").Key("Pages")
	collectProtectedPageObjects(pagesRoot, pagesRoot.Key("Resources"), protected, make(map[uint32]bool))
	if len(protected) == 0 {
		return nil
	}

	updateLen := fileSize - signedEnd
	if updateLen <= 0 || updateLen > 1<<28 {
		return nil
	}
	buf := make([]byte, updateLen)
	if _, err := file.ReadAt(buf, signedEnd); err != nil {
		return nil
	}

	for _, m := range objDefPattern.FindAllSubmatch(buf, -1) {
		id, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			continue
		}
		if protected[uint32(id)] {
			return fmt.Errorf("incremental update redefines object %d (a page, its content stream, or its resources), which DocMDP form-filling/annotation permissions do not allow", id)
		}
	}
	return nil
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
