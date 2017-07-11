package sign

import (
	"crypto"
	"crypto/x509"
	"io"
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

type VisualSignData struct {
	ObjectId uint32
	Length   int64
}

type InfoData struct {
	ObjectId uint32
	Length   int64
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
	Filesize                   int64
	InputFile                  *os.File
	OutputFile                 *os.File
	SignData                   SignData
	CatalogData                CatalogData
	VisualSignData             VisualSignData
	InfoData                   InfoData
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

	sign_data.ObjectId = uint32(rdr.XrefInformation.ItemCount) + 3

	// We do size+1 because we insert a newline.
	context := SignContext{
		Filesize:   size + 1,
		PDFReader:  rdr,
		InputFile:  input_file,
		OutputFile: output_file,
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

	err = context.SignPDF()
	if err != nil {
		return err
	}

	return nil
}

func (context *SignContext) SignPDF() error {
	// Copy old file into new file.
	if _, err := io.Copy(context.OutputFile, context.InputFile); err != nil {
		return err
	}

	err := context.OutputFile.Sync()
	if err != nil {
		return err
	}

	// File always needs an empty line after %%EOF.
	if _, err := context.OutputFile.Write([]byte("\n")); err != nil {
		return err
	}

	visual_signature, err := context.createVisualSignature()
	if err != nil {
		return err
	}

	context.VisualSignData.Length = int64(len(visual_signature))

	// Write the new catalog object.
	if _, err := context.OutputFile.Write([]byte(visual_signature)); err != nil {
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

	info, err := context.createInfo()
	if err != nil {
		return err
	}

	context.InfoData.Length = int64(len(info))

	// Write the new catalog object.
	if _, err := context.OutputFile.Write([]byte(info)); err != nil {
		return err
	}

	appended_bytes := context.Filesize + int64(len(catalog)) + int64(len(visual_signature)) + int64(len(info))

	// Positions are relative to old start position of xref table.
	byte_range_start_byte += appended_bytes
	signature_contents_start_byte += appended_bytes

	context.ByteRangeStartByte = byte_range_start_byte
	context.SignatureContentsStartByte = signature_contents_start_byte

	// Write the new signature object.
	if _, err := context.OutputFile.Write([]byte(signature_object)); err != nil {
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

	err = context.OutputFile.Sync()
	if err != nil {
		return err
	}

	return nil
}
