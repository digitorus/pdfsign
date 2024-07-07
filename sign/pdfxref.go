package sign

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	// Seek to the start of the xref table
	_, err := context.InputFile.Seek(context.PDFReader.XrefInformation.StartPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to xref table: %w", err)
	}

	// Read the existing xref table
	xrefContent := make([]byte, context.PDFReader.XrefInformation.Length)
	_, err = context.InputFile.Read(xrefContent)
	if err != nil {
		return fmt.Errorf("failed to read xref table: %w", err)
	}

	// Parse the xref header
	xrefLines := strings.Split(string(xrefContent), "\n")
	xrefHeader := strings.Fields(xrefLines[1])
	if len(xrefHeader) != 2 {
		return fmt.Errorf("invalid xref header format")
	}

	firstObjectID, err := strconv.Atoi(xrefHeader[0])
	if err != nil {
		return fmt.Errorf("invalid first object ID: %w", err)
	}

	itemCount, err := strconv.Atoi(xrefHeader[1])
	if err != nil {
		return fmt.Errorf("invalid item count: %w", err)
	}

	// Calculate new entries
	newEntries := []struct {
		startPosition int64
		name          string
	}{
		{context.Filesize, "visual signature"},
		{context.Filesize + context.VisualSignData.Length, "catalog"},
		{context.Filesize + context.VisualSignData.Length + context.CatalogData.Length, "info"},
		{context.Filesize + context.VisualSignData.Length + context.CatalogData.Length + context.InfoData.Length, "signature"},
	}

	// Write new xref table
	newXrefHeader := fmt.Sprintf("xref\n%d %d\n", firstObjectID, itemCount+len(newEntries))
	if _, err := context.OutputBuffer.Write([]byte(newXrefHeader)); err != nil {
		return fmt.Errorf("failed to write new xref header: %w", err)
	}

	// Write existing entries
	for i, line := range xrefLines[2:] {
		if i >= itemCount {
			break
		}
		if _, err := context.OutputBuffer.Write([]byte(line + "\n")); err != nil {
			return fmt.Errorf("failed to write existing xref entry: %w", err)
		}
	}

	// Write new entries
	for _, entry := range newEntries {
		xrefLine := fmt.Sprintf("%010d 00000 n \n", entry.startPosition)
		if _, err := context.OutputBuffer.Write([]byte(xrefLine)); err != nil {
			return fmt.Errorf("failed to write new xref entry for %s: %w", entry.name, err)
		}
	}

	return nil
}

func (context *SignContext) writeXrefStream() error {
	buffer := bytes.NewBuffer(nil)

	predictor := context.PDFReader.Trailer().Key("DecodeParms").Key("Predictor").Int64()

	var streamBytes []byte
	var err error

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

	new_xref := strconv.Itoa(int(context.SignData.ObjectId+1)) + " 0 obj\n"
	new_xref += "<< /Type /XRef /Length " + strconv.Itoa(len(streamBytes)) + " /Filter /FlateDecode /DecodeParms << /Columns 5 /Predictor 12 >> /W [ 1 3 1 ] /Prev " + strconv.FormatInt(context.PDFReader.XrefInformation.StartPos, 10) + " /Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+5, 10) + " /Index [ " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount, 10) + " 5 ] /" + new_info + " /" + new_root + " /ID [<" + id0 + "><" + id1 + ">] >>\n"
	if _, err := context.OutputBuffer.Write([]byte(new_xref)); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write([]byte("stream\n")); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write(streamBytes); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write([]byte("\nendstream\n")); err != nil {
		return err
	}

	return nil
}

func writeXrefStreamLine(b *bytes.Buffer, xreftype byte, offset int, gen byte) {
	b.WriteByte(xreftype)
	b.Write(encodeInt(offset))
	b.WriteByte(gen)
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
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
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
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	w.Close()

	return b.Bytes(), nil
}
