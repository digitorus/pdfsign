package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/mattetti/filebuffer"
)

type CatalogData struct {
	ObjectId   uint32
	RootString string
}

type TSA struct {
	URL      string
	Username string
	Password string
}

type RevocationFunction func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error

type SignData struct {
	Signature          SignDataSignature
	Signer             crypto.Signer
	DigestAlgorithm    crypto.Hash
	Certificate        *x509.Certificate
	CertificateChains  [][]*x509.Certificate
	TSA                TSA
	RevocationData     revocation.InfoArchival
	RevocationFunction RevocationFunction
	Appearance         Appearance

	// Updates contains raw byte updates for existing PDF objects.
	// The key is the object ID, use it with SignContext.UpdateObject.
	Updates map[uint32][]byte

	// PreSignCallback is called before the signature object is written.
	// It allows adding additional objects (e.g., initials) using the SignContext.
	PreSignCallback func(context *SignContext) error

	// CompressLevel determines compression level (zlib) for stream objects.
	CompressLevel int

	// ExtraSignedAttributes lets callers append additional CMS
	// SignedAttributes (RFC 5652 §11) keyed by custom OIDs to the PKCS#7
	// signature, in addition to the library defaults (Adobe RevocationData
	// OID 1.2.840.113583.1.1.8 and the signing-certificate-v2 attribute).
	//
	// These attributes ride inside the cryptographically protected
	// SignedAttributes set, so any tampering with their values breaks
	// pkcs7.Verify. An empty slice is the default and preserves the prior
	// behavior exactly.
	ExtraSignedAttributes []pkcs7.Attribute

	// SubFilter selects the signature encoding; the zero value keeps the legacy profile.
	SubFilter SubFilter

	// Context bounds the TSA HTTP request made when TSA.URL is set. If nil,
	// context.Background() is used. Cancelling it aborts an in-flight TSA
	// request immediately.
	Context context.Context

	objectId uint32
}

// Appearance represents the appearance of the signature
type Appearance struct {
	Visible bool

	Page        uint32
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64

	Image            []byte // Image data to use as signature appearance
	ImageAsWatermark bool   // If true, the text will be drawn over the image

	// Renderer allows providing a custom function to generate the appearance stream.
	// This is used by the pdf package to support complex appearances with multiple elements.
	Renderer func(context *SignContext, rect [4]float64) ([]byte, error)
}

type VisualSignData struct {
	pageObjectId uint32
	objectId     uint32
}

type InfoData struct {
	ObjectId uint32
}

// SubFilter names the encoding of the signature value (ISO 32000-2, table 255).
type SubFilter uint

const (
	// SubFilterAdbePKCS7Detached is the legacy /adbe.pkcs7.detached profile (default).
	SubFilterAdbePKCS7Detached SubFilter = iota

	// SubFilterETSICAdESDetached produces a PAdES baseline signature (ETSI EN 319 142-1).
	SubFilterETSICAdESDetached
)

//go:generate stringer -type=CertType
type CertType uint

const (
	CertificationSignature CertType = iota + 1
	ApprovalSignature
	UsageRightsSignature
	TimeStampSignature
)

//go:generate stringer -type=DocMDPPerm
type DocMDPPerm uint

const (
	DoNotAllowAnyChangesPerms DocMDPPerm = iota + 1
	AllowFillingExistingFormFieldsAndSignaturesPerms
	AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
)

type SignDataSignature struct {
	CertType   CertType
	DocMDPPerm DocMDPPerm
	Info       SignDataSignatureInfo
}

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	InputFile              io.ReadSeeker
	OutputFile             io.Writer
	OutputBuffer           *filebuffer.Buffer
	SignData               SignData
	CatalogData            CatalogData
	VisualSignData         VisualSignData
	InfoData               InfoData
	PDFReader              *pdf.Reader
	NewXrefStart           int64
	ByteRangeValues        []int64
	SignatureMaxLength     uint32
	SignatureMaxLengthBase uint32

	existingSignatures []SignData
	lastXrefID         uint32
	newXrefEntries     []xrefEntry
	updatedXrefEntries []xrefEntry

	// Map of Page Object ID to list of Annotation Object IDs to add.
	// This allows pre-sign callbacks to register annotations for pages that are also being modified by the signing process.
	ExtraAnnots map[uint32][]uint32

	// CompressLevel determines compression level (zlib) for stream objects.
	CompressLevel int
}
