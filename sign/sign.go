package sign

import (
	stdcontext "context"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"

	"github.com/mattetti/filebuffer"
)

var errSignatureTooLong = fmt.Errorf("signature too long")

const (
	estimatedTSAResponseSize      = 9000
	estimatedMLDSATSAResponseSize = 32 << 10
)

// SignFile signs a PDF file.
//
// Deprecated: Use pdf.OpenFile() and doc.Sign() instead.
func SignFile(input string, output string, sign_data SignData) error {
	input_file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer func() {
		_ = input_file.Close()
	}()

	output_file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer func() {
		cerr := output_file.Close()
		if err == nil {
			err = cerr
		}
	}()

	finfo, err := input_file.Stat()
	if err != nil {
		return err
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		return err
	}

	return Sign(input_file, output_file, rdr, size, sign_data)
}

// SignWithData signs a PDF document using the provided signature data.
// It performs a single incremental update.
//
// Deprecated: Use pdf.OpenFile() and doc.Sign() instead.
func SignWithData(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	if sign_data.Signature.Info.Date.IsZero() {
		sign_data.Signature.Info.Date = time.Now()
	}
	sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 2

	context := SignContext{
		PDFReader:              rdr,
		InputFile:              input,
		OutputFile:             output,
		SignData:               sign_data,
		SignatureMaxLengthBase: uint32(hex.EncodedLen(2048)),
		CompressLevel:          sign_data.CompressLevel,
	}

	// Fetch existing signatures
	existingSignatures, err := context.fetchExistingSignatures()
	if err != nil {
		return err
	}
	context.existingSignatures = existingSignatures

	err = context.SignPDF()
	if err != nil {
		return err
	}

	return nil
}

// Deprecated: Use pdf.OpenFile() and doc.Sign() instead.
func Sign(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	return SignWithData(input, output, rdr, size, sign_data)
}

// SignPDF performs the signature operation.
func (context *SignContext) SignPDF() error {
	// set defaults
	context.applyDefaults()

	if err := context.validateSignData(); err != nil {
		return err
	}

	const maxRetries = 5
	succeeded := false

	for retry := 0; retry < maxRetries; retry++ {
		context.resetContext()

		// Copy old file into new buffer.
		if err := context.copyInputToOutput(); err != nil {
			return err
		}

		// Calculate signature size
		if err := context.calculateSignatureSize(); err != nil {
			return err
		}

		// Execute PreSignCallback if provided.
		if context.SignData.PreSignCallback != nil {
			if err := context.SignData.PreSignCallback(context); err != nil {
				return fmt.Errorf("pre-sign callback failed: %w", err)
			}
		}

		// Add signature object
		if err := context.addSignatureObject(); err != nil {
			return err
		}

		// Handle visual signature
		if err := context.handleVisualSignature(); err != nil {
			return err
		}

		// Create and add catalog
		if err := context.addCatalog(); err != nil {
			return err
		}

		// Finalize PDF structure (xref, trailer, byte range)
		if err := context.finalizePDFStructure(); err != nil {
			return err
		}

		// Replace signature placeholder with actual signature
		if err := context.replaceSignature(); err != nil {
			if err == errSignatureTooLong {
				continue
			}
			return fmt.Errorf("failed to replace signature: %w", err)
		}

		// Success!
		succeeded = true
		break
	}

	if !succeeded {
		return fmt.Errorf("failed to fit signature into allocated buffer after %d attempts", maxRetries)
	}

	// Write final output
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	// We are still using the buffer here as refactoring that away is a larger task
	// involving the SignContext struct itself.
	file_content := context.OutputBuffer.Buff.Bytes()

	if _, err := context.OutputFile.Write(file_content); err != nil {
		return err
	}

	return nil
}

func (context *SignContext) applyDefaults() {
	if context.SignData.Signature.CertType == 0 {
		context.SignData.Signature.CertType = 1
	}
	if context.SignData.Signature.DocMDPPerm == 0 {
		context.SignData.Signature.DocMDPPerm = 1
	}
	if !context.SignData.DigestAlgorithm.Available() {
		context.SignData.DigestAlgorithm = defaultDigestForSigner(context.SignData.Signer)
	}
	if context.SignData.Appearance.Page == 0 {
		context.SignData.Appearance.Page = 1
	}
	context.SignData.Context = ensureContext(context.SignData.Context)
}

// validateSignData rejects parameters that cannot produce a conformant signature.
func (context *SignContext) validateSignData() error {
	switch context.SignData.SubFilter {
	case SubFilterAdbePKCS7Detached, SubFilterETSICAdESDetached:
	default:
		return fmt.Errorf("unsupported SubFilter value: %d", context.SignData.SubFilter)
	}

	if context.SignData.SubFilter == SubFilterETSICAdESDetached {
		// ETSI EN 319 142-1, 6.2.1: MD5 shall not be used; TS 119 312 excludes SHA-1.
		switch context.SignData.DigestAlgorithm {
		case crypto.MD5, crypto.SHA1:
			return fmt.Errorf("digest algorithm %s cannot be used for PAdES baseline signatures, use SHA-256 or stronger", context.SignData.DigestAlgorithm)
		}

		if err := context.validateRevocationData(); err != nil {
			return err
		}
	}

	if err := context.validateMLDSA(); err != nil {
		return err
	}

	if key := context.permsKey(); key != "" {
		if err := context.validatePermsSignature(key); err != nil {
			return err
		}
	}

	return nil
}

// validatePermsSignature enforces the rules for a signature that the catalog
// /Perms dictionary has to reference (ISO 32000-1 12.8.2.2 and 12.8.2.3): the
// permissions dictionary carries at most one /DocMDP and one /UR3 entry, and a
// DocMDP (certification) signature shall be the first signed field in the
// document. createCatalog relies on this when it writes the entry that points
// at the new signature.
func (context *SignContext) validatePermsSignature(key string) error {
	if context.PDFReader == nil {
		return nil
	}
	certType := context.SignData.Signature.CertType

	root := context.PDFReader.Trailer().Key("Root")
	if slices.Contains(root.Keys(), "Perms") {
		perms := root.Key("Perms")
		// A /Perms reference that cannot be resolved reads as null, so the
		// entry is checked by its key rather than by its resolved value.
		if perms.Kind() != pdf.Dict {
			return fmt.Errorf("cannot add a %s: the document catalog /Perms entry could not be read as a dictionary", certType)
		}
		if slices.Contains(perms.Keys(), key) {
			switch key {
			case "DocMDP":
				return errors.New("cannot add a certification signature: the document is already certified (catalog /Perms contains /DocMDP); use ApprovalSignature to sign an already signed document")
			default:
				return fmt.Errorf("cannot add a %s: the document catalog /Perms already contains /%s", certType, key)
			}
		}
	}

	if key == "DocMDP" && context.hasSignedField() {
		return errors.New("cannot add a certification signature: it must be the first signature in the document; use ApprovalSignature to sign an already signed document")
	}

	return nil
}

// maxFieldTreeDepth bounds the field tree walk; a conforming document nests
// fields far less deeply, and a crafted one must not recurse without end.
const maxFieldTreeDepth = 64

// walkSignatureFields calls fn for every terminal signature field in the
// AcroForm field tree until fn returns false. /FT is inheritable (ISO 32000-1
// Table 220), so a field takes it from its ancestors when it has none of its
// own; kids that carry no /T are the widget annotations of their parent, not
// fields. A visited set and a depth bound keep a crafted /Kids cycle from
// recursing without end.
func (context *SignContext) walkSignatureFields(fn func(field pdf.Value) bool) {
	fields := context.PDFReader.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	walkSignatureFieldsIn(fields, "", make(map[uint32]bool), 0, fn)
}

func walkSignatureFieldsIn(fields pdf.Value, inheritedFT string, visited map[uint32]bool, depth int, fn func(pdf.Value) bool) bool {
	if fields.Kind() != pdf.Array || depth > maxFieldTreeDepth {
		return true
	}
	for i := 0; i < fields.Len(); i++ {
		field := fields.Index(i)
		if id := field.GetPtr().GetID(); id > 0 {
			if visited[id] {
				continue
			}
			visited[id] = true
		}

		ft := field.Key("FT").Name()
		if ft == "" {
			ft = inheritedFT
		}

		kids := field.Key("Kids")
		hasChildFields := false
		for j := 0; kids.Kind() == pdf.Array && j < kids.Len(); j++ {
			if !kids.Index(j).Key("T").IsNull() {
				hasChildFields = true
				break
			}
		}

		if !hasChildFields {
			if ft == "Sig" && !fn(field) {
				return false
			}
			continue
		}
		if !walkSignatureFieldsIn(kids, ft, visited, depth+1, fn) {
			return false
		}
	}
	return true
}

// hasSignedField reports whether the document already contains a signature
// field with a value.
func (context *SignContext) hasSignedField() bool {
	signed := false
	context.walkSignatureFields(func(field pdf.Value) bool {
		signed = !field.Key("V").IsNull()
		return !signed
	})
	return signed
}

func defaultDigestForSigner(signer crypto.Signer) crypto.Hash {
	if signer != nil {
		if _, ok := signer.Public().(*mldsa.PublicKey); ok {
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

// validateMLDSA rejects configurations that would make the PDF signature
// dictionary disagree with the RFC 9882 CMS emitted by digitorus/pkcs7.
func (context *SignContext) validateMLDSA() error {
	if context.SignData.Signature.CertType == TimeStampSignature {
		return nil
	}
	if context.SignData.Signer == nil || context.SignData.Certificate == nil {
		return nil
	}

	signerPublic, signerIsMLDSA := context.SignData.Signer.Public().(*mldsa.PublicKey)
	certificatePublic, certificateIsMLDSA := context.SignData.Certificate.PublicKey.(*mldsa.PublicKey)
	if signerIsMLDSA != certificateIsMLDSA {
		return fmt.Errorf("signer and certificate must both use ML-DSA or both use a non-ML-DSA algorithm")
	}
	if !signerIsMLDSA {
		return nil
	}
	if signerPublic.Parameters() != certificatePublic.Parameters() {
		return fmt.Errorf("ML-DSA signer parameter set %s does not match certificate parameter set %s", signerPublic.Parameters(), certificatePublic.Parameters())
	}
	if context.SignData.DigestAlgorithm != crypto.SHA512 {
		return fmt.Errorf("ML-DSA PDF signatures require SHA-512 so /DigestMethod matches the RFC 9882 CMS digest, got %s", context.SignData.DigestAlgorithm)
	}
	return nil
}

// validateRevocationData prevents the legacy Adobe CMS attribute from being
// combined with the ETSI PAdES subfilter. Validation material for PAdES belongs
// in the PDF DSS dictionary at B-LT and later levels.
func (context *SignContext) validateRevocationData() error {
	if context.SignData.SubFilter == SubFilterETSICAdESDetached &&
		(len(context.SignData.RevocationData.CRL) > 0 || len(context.SignData.RevocationData.OCSP) > 0) {
		return fmt.Errorf("PAdES baseline signatures cannot embed Adobe revocation information; add validation material to the PDF DSS dictionary at B-LT or later")
	}
	return nil
}

// ensureContext returns ctx, defaulting to context.Background() when nil.
func ensureContext(ctx stdcontext.Context) stdcontext.Context {
	if ctx == nil {
		return stdcontext.Background()
	}
	return ctx
}

func (context *SignContext) resetContext() {
	context.OutputBuffer = filebuffer.New([]byte{})
	context.lastXrefID = 0
	context.newXrefEntries = nil
	context.updatedXrefEntries = nil
	context.ExtraAnnots = nil
	context.CatalogData = CatalogData{}
	context.VisualSignData = VisualSignData{}
}

func (context *SignContext) copyInputToOutput() error {
	if _, err := context.InputFile.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(context.OutputBuffer, context.InputFile); err != nil {
		return err
	}
	// File always needs an empty line after %%EOF.
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (context *SignContext) calculateSignatureSize() error {
	// Base size for signature.
	context.SignatureMaxLength = context.SignatureMaxLengthBase

	// If not a timestamp signature
	if context.SignData.Signature.CertType != TimeStampSignature {
		if context.SignData.Certificate == nil {
			return fmt.Errorf("certificate is required")
		}

		// Calculate signature size based on public key size
		var keySize int
		switch pub := context.SignData.Certificate.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = (pub.N.BitLen() + 7) / 8
		case *ecdsa.PublicKey:
			// ECDSA signature is (r, s) in ASN.1, roughly 2 * curve size + overhead
			curveBytes := (pub.Params().BitSize + 7) / 8
			keySize = 2*curveBytes + 32 // +32 for generous ASN.1 overhead
		case *mldsa.PublicKey:
			keySize = pub.Parameters().SignatureSize()
		default:
			keySize = 512 // Fallback default
		}
		context.SignatureMaxLength += uint32(hex.EncodedLen(keySize))

		// Add size of digest algorithm twice (for file digist and signing certificate attribute)
		context.SignatureMaxLength += uint32(hex.EncodedLen(context.SignData.DigestAlgorithm.Size() * 2))

		// Add size for my certificate.
		degenerated, err := pkcs7.DegenerateCertificate(context.SignData.Certificate.Raw)
		if err != nil {
			return fmt.Errorf("failed to degenerate certificate: %w", err)
		}

		context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))

		// Add size of the raw issuer which is added by AddSignerChain
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(context.SignData.Certificate.RawIssuer)))

		// Add size for certificate chain.
		var certificate_chain []*x509.Certificate
		if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
			certificate_chain = context.SignData.CertificateChains[0][1:]
		}

		if len(certificate_chain) > 0 {
			for _, cert := range certificate_chain {
				degenerated, err := pkcs7.DegenerateCertificate(cert.Raw)
				if err != nil {
					return fmt.Errorf("failed to degenerate certificate in chain: %w", err)
				}

				context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))
			}
		}

		// Fetch revocation data before adding signature placeholder.
		if err := context.fetchRevocationData(); err != nil {
			return fmt.Errorf("failed to fetch revocation data: %w", err)
		}
	}

	// Add estimated size for TSA.
	if context.SignData.TSA.URL != "" {
		estimatedSize := estimatedTSAResponseSize
		if context.SignData.Certificate != nil {
			if _, ok := context.SignData.Certificate.PublicKey.(*mldsa.PublicKey); ok {
				// A PQC TSA token can contain several large ML-DSA certificates
				// plus an ML-DSA signature. Reserve enough space up front so a
				// successful TSA request is not repeated merely to resize the PDF.
				estimatedSize = estimatedMLDSATSAResponseSize
			}
		}
		context.SignatureMaxLength += uint32(hex.EncodedLen(estimatedSize))
	}

	return nil
}

func (context *SignContext) addSignatureObject() error {
	var signature_object []byte
	switch context.SignData.Signature.CertType {
	case TimeStampSignature:
		signature_object = context.createTimestampPlaceholder()
	default:
		var err error
		signature_object, err = context.createSignaturePlaceholder()
		if err != nil {
			return fmt.Errorf("failed to create signature placeholder: %w", err)
		}
	}

	// Apply generic object updates if provided
	for id, content := range context.SignData.Updates {
		if err := context.UpdateObject(id, content); err != nil {
			return fmt.Errorf("failed to apply generic update for object %d: %w", id, err)
		}
	}

	// Write the new signature object
	var err error
	context.SignData.objectId, err = context.AddObject(signature_object)
	if err != nil {
		return fmt.Errorf("failed to add signature object: %w", err)
	}
	return nil
}

func (context *SignContext) handleVisualSignature() error {
	// Create visual signature (visible or invisible based on CertType)
	visible := false
	rectangle := [4]float64{0, 0, 0, 0}
	if context.SignData.Signature.CertType != ApprovalSignature && context.SignData.Appearance.Visible {
		return fmt.Errorf("visible signatures are only allowed for approval signatures")
	} else if context.SignData.Signature.CertType == ApprovalSignature && context.SignData.Appearance.Visible {
		visible = true
		rectangle = [4]float64{
			context.SignData.Appearance.LowerLeftX,
			context.SignData.Appearance.LowerLeftY,
			context.SignData.Appearance.UpperRightX,
			context.SignData.Appearance.UpperRightY,
		}
	}

	// Example usage: passing page number and default rect values
	visual_signature, err := context.createVisualSignature(visible, context.SignData.Appearance.Page, rectangle)
	if err != nil {
		return fmt.Errorf("failed to create visual signature: %w", err)
	}

	// Write the new visual signature object.
	context.VisualSignData.objectId, err = context.AddObject(visual_signature)
	if err != nil {
		return fmt.Errorf("failed to add visual signature object: %w", err)
	}

	if context.SignData.Appearance.Visible {
		inc_page_update, err := context.createIncPageUpdate(context.SignData.Appearance.Page, context.VisualSignData.objectId)
		if err != nil {
			return fmt.Errorf("failed to create incremental page update: %w", err)
		}
		if err := context.UpdateObject(context.VisualSignData.pageObjectId, inc_page_update); err != nil {
			return fmt.Errorf("failed to add incremental page update object: %w", err)
		}
	}
	return nil
}

func (context *SignContext) addCatalog() error {
	// Create a new catalog object
	catalog, err := context.createCatalog()
	if err != nil {
		return fmt.Errorf("failed to create catalog: %w", err)
	}

	// Write the new catalog object
	context.CatalogData.ObjectId, err = context.AddObject(catalog)
	if err != nil {
		return fmt.Errorf("failed to add catalog object: %w", err)
	}
	return nil
}

func (context *SignContext) finalizePDFStructure() error {
	// Write xref table
	if err := context.writeXref(); err != nil {
		return fmt.Errorf("failed to write xref: %w", err)
	}

	// Write trailer
	if err := context.writeTrailer(); err != nil {
		return fmt.Errorf("failed to write trailer: %w", err)
	}

	// Update byte range
	if err := context.updateByteRange(); err != nil {
		return fmt.Errorf("failed to update byte range: %w", err)
	}
	return nil
}
