package sign

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"time"

	"bitbucket.org/digitorus/pdf"
	"bitbucket.org/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"github.com/mattetti/filebuffer"
)

type CatalogData struct {
	ObjectId   uint32
	Length     int64
	RootString string
}

type TSA struct {
	URL      string
	Username string
	Password string
}

type RevocationFunction func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error

type SignData struct {
	ObjectId           uint32
	Signature          SignDataSignature
	Signer             crypto.Signer
	Certificate        *x509.Certificate
	CertificateChains  [][]*x509.Certificate
	TSA                TSA
	RevocationData     revocation.InfoArchival
	RevocationFunction RevocationFunction
}

type VisualSignData struct {
	ObjectId uint32
	Length   int64
}

type InfoData struct {
	ObjectId uint32
	Length   int64
}

type SignDataSignature struct {
	CertType   uint
	DocMDPPerm uint
	Info       SignDataSignatureInfo
}

const (
	ApprovalSignature = iota
	CertificationSignature
	UsageRightsSignature
)

const (
	DoNotAllowAnyChangesPerms = iota + 1
	AllowFillingExistingFormFieldsAndSignatures
	AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotations
)

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	Filesize                   int64
	InputFile                  io.ReadSeeker
	OutputFile                 io.Writer
	OutputBuffer               *filebuffer.Buffer
	SignData                   SignData
	CatalogData                CatalogData
	VisualSignData             VisualSignData
	InfoData                   InfoData
	PDFReader                  *pdf.Reader
	NewXrefStart               int64
	ByteRangeStartByte         int64
	SignatureContentsStartByte int64
	ByteRangeValues            []int64
	SignatureMaxLength         uint32
}

func SignFile(input string, output string, sign_data SignData) error {
	input_file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer input_file.Close()

	output_file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer output_file.Close()

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

func Sign(input io.ReadSeeker, output io.Writer, rdr *pdf.Reader, size int64, sign_data SignData) error {
	sign_data.ObjectId = uint32(rdr.XrefInformation.ItemCount) + 3

	// We do size+1 because we insert a newline.
	context := SignContext{
		Filesize:   size + 1,
		PDFReader:  rdr,
		InputFile:  input,
		OutputFile: output,
		VisualSignData: VisualSignData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount),
		},
		CatalogData: CatalogData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount) + 1,
		},
		InfoData: InfoData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount) + 2,
		},
		SignData: sign_data,
	}

	err := context.SignPDF()
	if err != nil {
		return err
	}

	return nil
}

func (context *SignContext) SignPDF() error {
	// set defaults
	if context.SignData.Signature.DocMDPPerm == 0 {
		context.SignData.Signature.DocMDPPerm = 1
	}

	context.OutputBuffer = filebuffer.New([]byte{})

	// Copy old file into new file.
	if _, err := io.Copy(context.OutputBuffer, context.InputFile); err != nil {
		return err
	}

	// File always needs an empty line after %%EOF.
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return err
	}

	// Base size for signature.
	context.SignatureMaxLength = uint32(hex.EncodedLen(512))

	switch string(context.SignData.Certificate.SignatureAlgorithm) {
	case "SHA1-RSA":
	case "ECDSA-SHA1":
	case "DSA-SHA1":
		context.SignatureMaxLength += uint32(hex.EncodedLen(128))
		break
	case "SHA256-RSA":
	case "ECDSA-SHA256":
	case "DSA-SHA256":
		context.SignatureMaxLength += uint32(hex.EncodedLen(256))
		break
	case "SHA384-RSA":
	case "ECDSA-SHA384":
		context.SignatureMaxLength += uint32(hex.EncodedLen(384))
		break
	case "SHA512-RSA":
	case "ECDSA-SHA512":
		context.SignatureMaxLength += uint32(hex.EncodedLen(512))
		break
	}

	// Add size for my certificate.
	degenerated, err := pkcs7.DegenerateCertificate(context.SignData.Certificate.Raw)
	if err != nil {
		return err
	}

	context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))

	// Add size for certificate chain.
	var certificate_chain []*x509.Certificate
	if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
		certificate_chain = context.SignData.CertificateChains[0][1:]
	}

	if len(certificate_chain) > 0 {
		for _, cert := range certificate_chain {
			degenerated, err := pkcs7.DegenerateCertificate(cert.Raw)
			if err != nil {
				return err
			}

			context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))
		}
	}

	// Add estimated size for TSA.
	// We can't kow actual size of TSA until after signing.
	if context.SignData.TSA.URL != "" {
		context.SignatureMaxLength += uint32(hex.EncodedLen(4000))
	}

	// Fetch revocation data before adding signature placeholder.
	// Revocation data can be quite large and we need to create enough space in the placeholder.
	context.fetchRevocationData()

	visual_signature, err := context.createVisualSignature()
	if err != nil {
		return err
	}

	context.VisualSignData.Length = int64(len(visual_signature))

	// Write the new catalog object.
	if _, err := context.OutputBuffer.Write([]byte(visual_signature)); err != nil {
		return err
	}

	catalog, err := context.createCatalog()
	if err != nil {
		return err
	}

	context.CatalogData.Length = int64(len(catalog))

	// Write the new catalog object.
	if _, err := context.OutputBuffer.Write([]byte(catalog)); err != nil {
		return err
	}

	// Create the signature object
	signature_object, byte_range_start_byte, signature_contents_start_byte := context.createSignaturePlaceholder()

	info, err := context.createInfo()
	if err != nil {
		return err
	}

	context.InfoData.Length = int64(len(info))

	// Write the new catalog object.
	if _, err := context.OutputBuffer.Write([]byte(info)); err != nil {
		return err
	}

	appended_bytes := context.Filesize + int64(len(catalog)) + int64(len(visual_signature)) + int64(len(info))

	// Positions are relative to old start position of xref table.
	byte_range_start_byte += appended_bytes
	signature_contents_start_byte += appended_bytes

	context.ByteRangeStartByte = byte_range_start_byte
	context.SignatureContentsStartByte = signature_contents_start_byte

	// Write the new signature object.
	if _, err := context.OutputBuffer.Write([]byte(signature_object)); err != nil {
		return err
	}

	// Calculate the new start position of the xref table.
	context.NewXrefStart = appended_bytes + int64(len(signature_object))

	if err := context.writeXref(); err != nil {
		return err
	}

	if err := context.writeTrailer(); err != nil {
		return err
	}

	if err := context.updateByteRange(); err != nil {
		return err
	}

	if err := context.replaceSignature(); err != nil {
		return err
	}

	context.OutputBuffer.Seek(0, 0)
	file_content := context.OutputBuffer.Buff.Bytes()

	context.OutputFile.Write(file_content)

	return nil
}
