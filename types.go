package pdfsign

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/digitorus/pdfsign/extract"
	"github.com/digitorus/pdfsign/fonts"
	"github.com/digitorus/pdfsign/forms"
	"github.com/digitorus/pdfsign/images"
	"github.com/digitorus/pdfsign/initials"
	"github.com/digitorus/pdfsign/sign"
)

// SignatureType represents the type of signature.
type SignatureType int

const (
	// ApprovalSignature indicates that the signer approves the content of the document.
	// This is the most common type of signature.
	ApprovalSignature SignatureType = iota

	// CertificationSignature indicates that the signer is the author of the document
	// and specifies what changes are permitted after signing.
	CertificationSignature

	// DocumentTimestamp is a document-level timestamp that proves the document existed
	// at a specific time without certifying authorship.
	DocumentTimestamp
)

// Permission represents document modification permissions for certification signatures.
type Permission int

const (
	// NoChanges guarantees that the document has not been modified in any way.
	// Any subsequent change will invalidate the signature.
	NoChanges Permission = iota + 1

	// AllowFormFilling permits the user to fill in form fields and sign the document,
	// but not to add comments or annotations.
	AllowFormFilling

	// AllowFormFillingAndAnnotations permits the user to fill forms, sign, and add
	// comments or annotations (e.g., sticky notes).
	AllowFormFillingAndAnnotations
)

// Format represents the signature format.
type Format int

const (
	// DefaultFormat allows the library to choose the best available format (currently PAdES-B-LT).
	// This format embeds revocation information (OCSP/CRL) to ensure long-term validation support.
	DefaultFormat Format = iota

	// PAdES_B (Baseline-Basic) creates a lightweight signature containing only the signer's
	// certificate and the signed hash. It DOES NOT embed revocation information.
	// Use this if you need minimal file size or if the signature is short-lived.
	PAdES_B

	// PAdES_B_T (Baseline-Timestamp) extends PAdES-B by requiring a timestamp from a
	// trusted Timestamp Authority (TSA). This proves the signature existed at a specific time.
	// Requires a TSA URL to be configured.
	PAdES_B_T

	// PAdES_B_LT (Baseline-Long-Term) extends PAdES-B-T by embedding validation material
	// (OCSP responses and/or CRLs) into the signature. This allows the signature to be validated
	// even if the original CA services are offline or the certificate has expired (provided
	// the revocation data was valid at signing time).
	PAdES_B_LT

	// PAdES_B_LTA (Baseline-Long-Term-Availability) is not yet supported.
	// It would add document-level timestamps to protect the LTV data over time.
	PAdES_B_LTA

	// C2PA is Content Authenticity signature format (not yet supported).
	C2PA

	// JAdES_B_T is JAdES Baseline B-T level (not yet supported).
	JAdES_B_T
)

// Compliance represents PDF/A compliance levels.
type Compliance int

const (
	// DefaultCompliance means no specific compliance enforcement (default).
	// The library will produce a valid PDF signature but will not strictly enforce all PDF/A constraints.
	DefaultCompliance Compliance = iota

	// PDFA_1B is not yet enforced.
	PDFA_1B

	// PDFA_2B is not yet enforced.
	PDFA_2B

	// PDFA_3B is not yet enforced.
	PDFA_3B
)

// Result contains the result of a Write operation.
type Result struct {
	Signatures []SignatureInfo
	Document   *Document
}

// SignatureInfo contains information about a signature.
type SignatureInfo struct {
	SignerName  string
	SigningTime time.Time
	Reason      string
	Location    string
	Contact     string
	Certificate *x509.Certificate
	Timestamp   *TimestampInfo
	ByteRange   [4]int64
	Format      Format
}

// TimestampInfo contains information about a timestamp.
type TimestampInfo struct {
	Time        time.Time
	Authority   string
	Certificate *x509.Certificate
}

// Font is an alias for fonts.Font for backward compatibility.
// Deprecated: Use fonts.Font directly.
type Font = fonts.Font

// FontMetrics is an alias for fonts.Metrics for backward compatibility.
// Deprecated: Use fonts.Metrics directly.
type FontMetrics = fonts.Metrics

// Image is an alias for images.Image for backward compatibility.
// Deprecated: Use images.Image directly.
type Image = images.Image

// Signature is an alias for extract.Signature for backward compatibility.
// Deprecated: Use extract.Signature directly.
type Signature = extract.Signature

// FormField is an alias for forms.FormField for backward compatibility.
// Deprecated: Use forms.FormField directly.
type FormField = forms.FormField

// Position is an alias for initials.Position for backward compatibility.
// Deprecated: Use initials.Position directly.
type Position = initials.Position

const (
	// TopLeft positions at top-left corner.
	TopLeft = initials.TopLeft
	// TopRight positions at top-right corner.
	TopRight = initials.TopRight
	// BottomLeft positions at bottom-left corner.
	BottomLeft = initials.BottomLeft
	// BottomRight positions at bottom-right corner.
	BottomRight = initials.BottomRight
)

// InitialsConfig is an alias for initials.Config for backward compatibility.
// Deprecated: Use initials.Config directly.
type InitialsConfig = initials.Config

// InitialsBuilder is an alias for initials.Builder for backward compatibility.
// Deprecated: Use initials.Builder directly.
type InitialsBuilder = initials.Builder

const (
	// PDF coordinates are defined in "user space units". By default, one unit
	// corresponds to one "point" (1/72 of an inch).
	//
	// These constants can be used to convert from physical units to PDF points.

	// Millimeter represents the number of PDF user space units in one millimeter.
	Millimeter = 72.0 / 25.4
	// Centimeter represents the number of PDF user space units in one centimeter.
	Centimeter = 72.0 / 2.54
	// Inch represents the number of PDF user space units in one inch.
	Inch = 72.0
)

// StandardFontType is an alias for fonts.StandardType for backward compatibility.
// Deprecated: Use fonts.StandardType directly.
type StandardFontType = fonts.StandardType

const (
	// Helvetica is the standard Helvetica font.
	Helvetica = fonts.Helvetica
	// HelveticaBold is bold Helvetica.
	HelveticaBold = fonts.HelveticaBold
	// HelveticaOblique is oblique Helvetica.
	HelveticaOblique = fonts.HelveticaOblique
	// TimesRoman is Times Roman font.
	TimesRoman = fonts.TimesRoman
	// TimesBold is bold Times Roman.
	TimesBold = fonts.TimesBold
	// Courier is Courier font.
	Courier = fonts.Courier
	// CourierBold is bold Courier.
	CourierBold = fonts.CourierBold
)

// StandardFont returns a Font for a standard PDF font.
// Deprecated: Use fonts.Standard directly.
func StandardFont(ft StandardFontType) *Font {
	return fonts.Standard(ft)
}

// ParseTTFMetrics parses a TrueType font file and extracts glyph metrics.
// Deprecated: Use fonts.ParseTTFMetrics directly.
func ParseTTFMetrics(data []byte) (*FontMetrics, error) {
	return fonts.ParseTTFMetrics(data)
}

// SignBuilder builds a signature configuration.
type SignBuilder struct {
	doc             *Document
	signer          crypto.Signer
	cert            *x509.Certificate
	chains          [][]*x509.Certificate
	reason          string
	location        string
	contact         string
	signerName      string
	sigType         SignatureType
	permission      Permission
	format          Format
	appearance      *Appearance
	appPage         int
	appX, appY      float64
	tsa             string
	tsaUser         string
	tsaPass         string
	digest          crypto.Hash
	c2paCreator     string
	c2paClaim       string
	revocationFunc  sign.RevocationFunction
	preferCRL       bool
	revocationCache sign.RevocationCache
	unit            float64
}

// RevocationCache sets the cache for revocation data (CRL/OCSP).
func (b *SignBuilder) RevocationCache(cache sign.RevocationCache) *SignBuilder {
	b.revocationCache = cache
	return b
}

// Reason sets the signing reason (e.g., "I agree to the terms", "I am the author").
// This text appears in the signature widget and signature properties.
func (b *SignBuilder) Reason(reason string) *SignBuilder {
	b.reason = reason
	return b
}

// Location specifies the physical location of the signer (e.g., "New York, USA").
func (b *SignBuilder) Location(location string) *SignBuilder {
	b.location = location
	return b
}

// Contact provides contact information for the signer (e.g., email address or phone number)
// to allow recipients to verify the signature.
func (b *SignBuilder) Contact(contact string) *SignBuilder {
	b.contact = contact
	return b
}

// SignerName sets the visual name of the signer.
// Ideally this matches the Common Name (CN) in the signing certificate, but it can be customized.
func (b *SignBuilder) SignerName(name string) *SignBuilder {
	b.signerName = name
	return b
}

// Type specifies the type of signature (Approval, Certification, or Timestamp).
// Default is ApprovalSignature if not specified.
// Certification signatures must be the first signature in the document.
func (b *SignBuilder) Type(t SignatureType) *SignBuilder {
	b.sigType = t
	return b
}

// Permission limits what changes are allowed to the document after signing.
// This is only applicable for CertificationSignatures.
// Default is AllowFormFilling if not specified for certification.
func (b *SignBuilder) Permission(p Permission) *SignBuilder {
	b.permission = p
	return b
}

// Format configures the signature format (e.g., PAdES_B, PAdES_B_LT).
// This determines whether revocation info is embedded (LTV) and other compliance features.
// Default is PAdES_B_LT-like behavior (revocation embedded) if not specified.
func (b *SignBuilder) Format(f Format) *SignBuilder {
	b.format = f
	return b
}

// Unit sets the coordinate system scale for subsequent calls to Appearance.
// By default, the unit is 1.0 (one PDF point = 1/72 inch).
//
// Example:
//
//	// Place signature at (20mm, 50mm)
//	builder.Unit(pdfsign.Millimeter).Appearance(app, 1, 20, 50)
func (b *SignBuilder) Unit(u float64) *SignBuilder {
	b.unit = u
	return b
}

// Appearance sets the visual appearance of the signature widget.
// The appearance can include text, images, or graphics.
//
//   - page: The page number to place the signature on (starting from 1 for the first page).
//   - x, y: The coordinates in the current Unit (default is PDF points).
//     (0, 0) is usually the bottom-left corner of the page.
func (b *SignBuilder) Appearance(a *Appearance, page int, x, y float64) *SignBuilder {
	b.appearance = a
	b.appPage = page
	b.appX = x
	b.appY = y
	return b
}

// Timestamp enables RFC 3161 timestamping using the provided Time Stamp Authority (TSA) URL.
// The timestamp is embedded in the signature to prove the time of signing.
func (b *SignBuilder) Timestamp(url string) *SignBuilder {
	b.tsa = url
	return b
}

// tsaURL is internal method to set TSA URL.
func (b *SignBuilder) tsaURL(url string) *SignBuilder {
	b.tsa = url
	return b
}

// TimestampAuth sets TSA authentication credentials.
func (b *SignBuilder) TimestampAuth(username, password string) *SignBuilder {
	b.tsaUser = username
	b.tsaPass = password
	return b
}

// Digest sets the hash algorithm for the signature (e.g., crypto.SHA256).
// Default is SHA256 if not specified.
func (b *SignBuilder) Digest(hash crypto.Hash) *SignBuilder {
	b.digest = hash
	return b
}

// CertificateChains sets the certificate chains for the signature.
// Deprecated: Use the variadic arguments in `doc.Sign` instead to provide intermediate certificates.
func (b *SignBuilder) CertificateChains(chains [][]*x509.Certificate) *SignBuilder {
	b.chains = chains
	return b
}

// C2PACreator sets the C2PA creator tool name.
func (b *SignBuilder) C2PACreator(creator string) *SignBuilder {
	b.c2paCreator = creator
	return b
}

// C2PAClaimGenerator sets the C2PA claim generator.
func (b *SignBuilder) C2PAClaimGenerator(generator string) *SignBuilder {
	b.c2paClaim = generator
	return b
}

// RevocationFunction sets a custom function to handle revocation fetching (CRL/OCSP).
// If not set, the library will attempt to fetch from distribution points via HTTP.
func (b *SignBuilder) RevocationFunction(fn sign.RevocationFunction) *SignBuilder {
	b.revocationFunc = fn
	return b
}

// PreferCRL sets whether to prefer CRL over OCSP for revocation checks.
// By default, the library prefers OCSP (if available) as it produces smaller signatures.
func (b *SignBuilder) PreferCRL(prefer bool) *SignBuilder {
	b.preferCRL = prefer
	return b
}

// VerifyBuilder provides a fluent API for configuring and executing PDF signature verification.
// Verification is performed lazily when result accessor methods (Valid, Signatures, Err) are called.
type VerifyBuilder struct {
	doc                   *Document
	trustedRoots          *x509.CertPool
	trustEmbedded         bool
	checkRevocation       bool
	allowOCSP             bool
	allowCRL              bool
	externalChecks        bool
	validateFullChain     bool
	validateTimestampCert bool
	atTime                *time.Time
	trustSignatureTime    bool
	requireDigSig         bool
	requireNonRepud       bool
	allowedEKUs           []x509.ExtKeyUsage
	minRSAKeySize         int
	minECDSAKeySize       int
	allowedAlgorithms     []x509.PublicKeyAlgorithm

	// Lazy execution state
	executed   bool
	signatures []SignatureVerifyResult
	document   DocumentInfo
	err        error
}

// TrustedRoots sets the pool of root certificates that are trusted to verify the signer's certificate chain.
// If not set, verification will fail unless TrustSelfSigned(true) is enabled.
func (b *VerifyBuilder) TrustedRoots(pool *x509.CertPool) *VerifyBuilder {
	b.trustedRoots = pool
	return b
}

// TrustSelfSigned allows verification to succeed even if the certificate is self-signed or
// not signed by a CA in the TrustedRoots pool.
//
// WARNING: Enabling this bypasses certificate chain trust validation and should only be used
// for testing or internal environments where certificates are manually trusted.
func (b *VerifyBuilder) TrustSelfSigned(trust bool) *VerifyBuilder {
	b.trustEmbedded = trust
	return b
}

// CheckRevocation enables or disables all revocation checks (OCSP and CRL).
// If enabled, the library will attempt to verify if the certificate has been revoked.
func (b *VerifyBuilder) CheckRevocation(check bool) *VerifyBuilder {
	b.checkRevocation = check
	return b
}

// AllowOCSP allows OCSP for revocation checking.
func (b *VerifyBuilder) AllowOCSP(allow bool) *VerifyBuilder {
	b.allowOCSP = allow
	return b
}

// AllowCRL allows CRL for revocation checking.
func (b *VerifyBuilder) AllowCRL(allow bool) *VerifyBuilder {
	b.allowCRL = allow
	return b
}

// ExternalChecks enables or disables network access to fetch revocation data from the web.
// If enabled, the library will attempt to contact OCSP responders and download CRLs
// from distribution points specified in the certificates.
func (b *VerifyBuilder) ExternalChecks(enable bool) *VerifyBuilder {
	b.externalChecks = enable
	return b
}

// AtTime sets the point in time at which the certificate chain's validity should be checked.
// By default, certificates are checked against the current system time.
func (b *VerifyBuilder) AtTime(t time.Time) *VerifyBuilder {
	b.atTime = &t
	return b
}

// ValidateFullChain sets whether to enforce cryptographic policy constraints (key size, algorithms) on the entire chain.
//
// By default (false), these constraints are only enforced on the leaf (signer) certificate.
// Revocation and standard trust verification are always performed on the full chain.
func (b *VerifyBuilder) ValidateFullChain(validate bool) *VerifyBuilder {
	b.validateFullChain = validate
	return b
}

// ValidateTimestampCertificates when true, validates the timestamp token's signing certificate.
func (b *VerifyBuilder) ValidateTimestampCertificates(validate bool) *VerifyBuilder {
	b.validateTimestampCert = validate
	return b
}

// TrustSignatureTime determines whether to use the time specified in the PDF signature
// dictionary as the validation time, rather than the current system time.
// Note: This time is provided by the signer and should only be trusted if verified by a TSA.
func (b *VerifyBuilder) TrustSignatureTime(trust bool) *VerifyBuilder {
	b.trustSignatureTime = trust
	return b
}

// RequireDigitalSignature requires the Digital Signature key usage bit.
func (b *VerifyBuilder) RequireDigitalSignature(require bool) *VerifyBuilder {
	b.requireDigSig = require
	return b
}

// RequireNonRepudiation requires the Non-Repudiation key usage bit.
func (b *VerifyBuilder) RequireNonRepudiation(require bool) *VerifyBuilder {
	b.requireNonRepud = require
	return b
}

// AllowedEKUs sets the allowed Extended Key Usages.
func (b *VerifyBuilder) AllowedEKUs(ekus ...x509.ExtKeyUsage) *VerifyBuilder {
	b.allowedEKUs = ekus
	return b
}

// MinRSAKeySize constrains the minimum bit size for RSA keys.
func (b *VerifyBuilder) MinRSAKeySize(bits int) *VerifyBuilder {
	b.minRSAKeySize = bits
	return b
}

// MinECDSAKeySize constrains the minimum curve size for ECDSA keys.
func (b *VerifyBuilder) MinECDSAKeySize(bits int) *VerifyBuilder {
	b.minECDSAKeySize = bits
	return b
}

// AllowedAlgorithms restricts the permitted public key algorithms (e.g. x509.RSA, x509.ECDSA).
func (b *VerifyBuilder) AllowedAlgorithms(algos ...x509.PublicKeyAlgorithm) *VerifyBuilder {
	b.allowedAlgorithms = algos
	return b
}

// Strict is a convenience method that enables all security and revocation checks.
// It sets:
//   - `CheckRevocation(true)`
//   - `ExternalChecks(true)`
//   - `ValidateFullChain(true)`
//   - `RequireDigitalSignature(true)`
//   - `RequireNonRepudiation(true)`
//   - `TrustSelfSigned(false)`
func (b *VerifyBuilder) Strict() *VerifyBuilder {
	b.requireDigSig = true
	b.requireNonRepud = true
	b.externalChecks = true
	b.validateFullChain = true
	b.trustEmbedded = false
	return b
}

// --- Result Accessor Methods (trigger lazy execution) ---

// Valid returns true if all signatures are valid. Triggers verification if not already executed.
func (b *VerifyBuilder) Valid() bool {
	b.execute()
	if b.err != nil {
		return false
	}
	for _, sig := range b.signatures {
		if !sig.Valid {
			return false
		}
	}
	return true
}

// Signatures returns the verification results for each signature. Triggers verification if not already executed.
func (b *VerifyBuilder) Signatures() []SignatureVerifyResult {
	b.execute()
	return b.signatures
}

// Document returns document metadata. Triggers verification if not already executed.
func (b *VerifyBuilder) Document() DocumentInfo {
	b.execute()
	return b.document
}

// Err returns any error that occurred during verification. Triggers verification if not already executed.
func (b *VerifyBuilder) Err() error {
	b.execute()
	return b.err
}

// Count returns the number of signatures found. Triggers verification if not already executed.
func (b *VerifyBuilder) Count() int {
	b.execute()
	return len(b.signatures)
}
