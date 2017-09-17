package sign

import (
	"errors"
	"strconv"
	"encoding/hex"
	"compress/zlib"
	"bytes"
	"encoding/binary"
)

func (context *SignContext) writeXref() error {

	if context.PDFReader.XrefInformation.Type == "table" {
		if err := context.writeXrefTable(); err != nil {
			return err
		}
	} else if context.PDFReader.XrefInformation.Type == "stream" {
		if err := context.writeXrefStream(); err != nil {
			return err
		}
	} else {
		return errors.New("Unkwn xref type: " + context.PDFReader.XrefInformation.Type)
	}

	return nil
}

func (context *SignContext) writeXrefTable() error {
	// @todo: maybe we need a prev here too.
	xref_size := "xref\n0 " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount, 10)
	new_xref_size := "xref\n0 " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+4, 10)

	if _, err := context.OutputFile.Write([]byte(new_xref_size)); err != nil {
		return err
	}

	// Write the old xref table to the output pdf.
	if err := writePartFromSourceFileToTargetFile(context.InputFile, context.OutputFile, context.PDFReader.XrefInformation.StartPos+int64(len(xref_size)), context.PDFReader.XrefInformation.Length-int64(len(xref_size))); err != nil {
		return err
	}

	// Create the new catalog xref line.
	visual_signature_object_start_position := strconv.FormatInt(context.Filesize, 10)
	visual_signature_xref_line := leftPad(visual_signature_object_start_position, "0", 10-len(visual_signature_object_start_position)) + " 00000 n \n"

	// Write the new catalog xref line.
	if _, err := context.OutputFile.Write([]byte(visual_signature_xref_line)); err != nil {
		return err
	}

	// Create the new catalog xref line.
	catalog_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length, 10)
	catalog_xref_line := leftPad(catalog_object_start_position, "0", 10-len(catalog_object_start_position)) + " 00000 n \n"

	// Write the new catalog xref line.
	if _, err := context.OutputFile.Write([]byte(catalog_xref_line)); err != nil {
		return err
	}

	// Create the new signature xref line.
	info_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length, 10)
	info_xref_line := leftPad(info_object_start_position, "0", 10-len(info_object_start_position)) + " 00000 n \n"

	// Write the new signature xref line.
	if _, err := context.OutputFile.Write([]byte(info_xref_line)); err != nil {
		return err
	}

	// Create the new signature xref line.
	signature_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length+context.InfoData.Length, 10)
	signature_xref_line := leftPad(signature_object_start_position, "0", 10-len(signature_object_start_position)) + " 00000 n \n"

	// Write the new signature xref line.
	if _, err := context.OutputFile.Write([]byte(signature_xref_line)); err != nil {
		return err
	}

	return nil
}

func (context *SignContext) writeXrefStream() error {
	buffer := bytes.NewBuffer(nil)

	predictor := context.PDFReader.Trailer().Key("DecodeParms").Key("Predictor").Int64()

	streamBytes := []byte{}
	err := errors.New("")

	writeXrefStreamLine(buffer, 1, int(context.Filesize), 0)
	writeXrefStreamLine(buffer, 1, int(context.Filesize+context.VisualSignData.Length), 0)
	writeXrefStreamLine(buffer, 1, int(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length), 0)
	writeXrefStreamLine(buffer, 1, int(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length+context.InfoData.Length), 0)
	writeXrefStreamLine(buffer, 1, int(context.NewXrefStart), 0)

	// If original uses PNG Sub, use that.
	if predictor == 11 {
		streamBytes, err = EncodePNGSUBBytes(5, buffer.Bytes())
		if err != nil {
			return err
		}
	} else {
		// Do PNG - Up by default.
		streamBytes, err = EncodePNGUPBytes(5, buffer.Bytes())
		if err != nil {
			return err
		}
	}


	new_info := "Info " + strconv.FormatInt(int64(context.InfoData.ObjectId), 10) + " 0 R"
	new_root := "Root " + strconv.FormatInt(int64(context.CatalogData.ObjectId), 10) + " 0 R"

	id := context.PDFReader.Trailer().Key("ID")

	id0 := hex.EncodeToString([]byte(id.Index(0).RawString()))
	id1 := hex.EncodeToString([]byte(id.Index(0).RawString()))

	new_xref := strconv.Itoa(int(context.SignData.ObjectId + 1)) + " 0 obj\n"
	new_xref += "<< /Type /XRef /Length " + strconv.Itoa(len(streamBytes))  + " /Filter /FlateDecode /DecodeParms << /Columns 5 /Predictor 12 >> /W [ 1 3 1 ] /Prev " +  strconv.FormatInt(context.PDFReader.XrefInformation.StartPos, 10) + " /Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+5, 10) + " /Index [ " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount, 10) + " 5 ] /" + new_info + " /" + new_root + " /ID [<" + id0 + "><" + id1 + ">] >>\n"
	if _, err := context.OutputFile.Write([]byte(new_xref)); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write([]byte("stream\n")); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write(streamBytes); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write([]byte("\nendstream\n")); err != nil {
		return err
	}

	return nil
}

func writeXrefStreamLine(b *bytes.Buffer, xreftype byte, offset int, gen byte) {
	b.WriteByte(xreftype);
	b.Write(encodeInt(offset));
	b.WriteByte(gen);
}

func encodeInt(i int) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(i))
	return result[1:4]
}

func EncodePNGSUBBytes(columns int, data []byte) ([]byte, error) {
	rowCount := len(data) / columns
	if len(data)%columns != 0 {
		return nil, errors.New("Invalid row/column length")
	}

	buffer := bytes.NewBuffer(nil)
	tmpRowData := make([]byte, columns)
	for i := 0; i < rowCount; i++ {
		rowData := data[columns*i : columns*(i+1)]
		tmpRowData[0] = rowData[0]
		for j := 1; j < columns; j++ {
			tmpRowData[j] = byte(int(rowData[j]-rowData[j-1]) % 256)
		}

		buffer.WriteByte(1)
		buffer.Write(tmpRowData)
	}

	data = buffer.Bytes()

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()

	return b.Bytes(), nil
}


func EncodePNGUPBytes(columns int, data []byte) ([]byte, error) {
	rowCount := len(data) / columns
	if len(data)%columns != 0 {
		return nil, errors.New("Invalid row/column length")
	}

	prevRowData := make([]byte, columns)

	// Initially all previous data is zero.
	for i := 0; i < columns; i++ {
		prevRowData[i] = 0
	}

	buffer := bytes.NewBuffer(nil)
	tmpRowData := make([]byte, columns)
	for i := 0; i < rowCount; i++ {
		rowData := data[columns*i : columns*(i+1)]
		for j := 0; j < columns; j++ {
			tmpRowData[j] = byte(int(rowData[j]-prevRowData[j]) % 256)
		}

		// Save the previous row for prediction.
		copy(prevRowData, rowData)

		buffer.WriteByte(2)
		buffer.Write(tmpRowData)
	}

	data = buffer.Bytes()

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()

	return b.Bytes(), nil
}