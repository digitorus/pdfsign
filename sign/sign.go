package sign

import (
	"crypto"
	"crypto/x509"
	"os"
	"time"

	"bitbucket.org/digitorus/pdf"
)

type CatalogData struct {
	ObjectId   uint32
	Length     int64
	RootString string
}

type SignData struct {
	ObjectId         uint32
	Signature        SignDataSignature
	Signer           crypto.Signer
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

type SignDataSignature struct {
	Approval bool
	CertType uint32
	Info     SignDataSignatureInfo
}

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	InputFile                  *os.File
	OutputFile                 *os.File
	SignData                   SignData
	CatalogData                CatalogData
	PDFReader                  *pdf.Reader
	NewXrefStart               int64
	ByteRangeStartByte         int64
	SignatureContentsStartByte int64
	ByteRangeValues            []int64
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

	sign_data.ObjectId = uint32(rdr.XrefInformation.ItemCount) + 1

	context := SignContext{
		PDFReader:  rdr,
		InputFile:  input_file,
		OutputFile: output_file,
		CatalogData: CatalogData{
			ObjectId: uint32(rdr.XrefInformation.ItemCount),
		},
		SignData: sign_data,
	}

	err = context.SignPDF()
	if err != nil {
		return err
	}

	return nil
}

func (context *SignContext) SignPDF() error {
	// Write the PDF file to the output up til the xref.
	if err := writePartFromSourceFileToTargetFile(context.InputFile, context.OutputFile, 0, context.PDFReader.XrefInformation.StartPos); err != nil {
		return err
	}

	catalog, err := context.createCatalog()
	if err != nil {
		return err
	}

	context.CatalogData.Length = int64(len(catalog))

	// Write the new catalog object.
	if _, err := context.OutputFile.Write([]byte(catalog)); err != nil {
		return err
	}

	// Create the signature object
	signature_object, byte_range_start_byte, signature_contents_start_byte := context.createSignaturePlaceholder()

	// Positions are relative to old start position of xref table.
	byte_range_start_byte += context.PDFReader.XrefInformation.StartPos + int64(len(catalog))
	signature_contents_start_byte += context.PDFReader.XrefInformation.StartPos + int64(len(catalog))

	context.ByteRangeStartByte = byte_range_start_byte
	context.SignatureContentsStartByte = signature_contents_start_byte

	// Write the new signature object.
	if _, err := context.OutputFile.Write([]byte(signature_object)); err != nil {
		return err
	}

	// Calculate the new start position of the xref table.
	context.NewXrefStart = context.PDFReader.XrefInformation.StartPos + int64(len(signature_object)) + int64(len(catalog))

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

	return nil
}
