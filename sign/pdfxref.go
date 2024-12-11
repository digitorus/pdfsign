package sign

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type xrefEntry struct {
	ID     uint32
	Offset int64
}

const (
	xrefStreamColumns   = 5
	xrefStreamPredictor = 12
	pngSubPredictor     = 11
	pngUpPredictor      = 12
	objectFooter        = "\nendobj\n"
)

func (context *SignContext) addObject(object []byte) (uint32, error) {
	if context.lastXrefID == 0 {
		lastXrefID, err := context.getLastObjectIDFromXref()
		if err != nil {
			return 0, fmt.Errorf("failed to get last object ID: %w", err)
		}
		context.lastXrefID = lastXrefID
	}

	objectID := context.lastXrefID + uint32(len(context.newXrefEntries)) + 1
	context.newXrefEntries = append(context.newXrefEntries, xrefEntry{
		ID:     objectID,
		Offset: int64(context.OutputBuffer.Buff.Len()) + 1,
	})

	// Write the object header
	if _, err := context.OutputBuffer.Write([]byte(fmt.Sprintf("\n%d 0 obj\n", objectID))); err != nil {
		return 0, fmt.Errorf("failed to write object header: %w", err)
	}

	// Write the object content
	object = bytes.TrimSpace(object)
	if _, err := context.OutputBuffer.Write(object); err != nil {
		return 0, fmt.Errorf("failed to write object content: %w", err)
	}

	// Write the object footer
	if _, err := context.OutputBuffer.Write([]byte(objectFooter)); err != nil {
		return 0, fmt.Errorf("failed to write object footer: %w", err)
	}

	return objectID, nil
}

// writeXref writes the cross-reference table or stream based on the PDF type.
func (context *SignContext) writeXref() error {
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline before xref: %w", err)
	}
	context.NewXrefStart = int64(context.OutputBuffer.Buff.Len())

	switch context.PDFReader.XrefInformation.Type {
	case "table":
		return context.writeIncrXrefTable()
	case "stream":
		return context.writeXrefStream()
	default:
		return fmt.Errorf("unknown xref type: %s", context.PDFReader.XrefInformation.Type)
	}
}

func (context *SignContext) getLastObjectIDFromXref() (uint32, error) {
	// Seek to the start of the xref table
	if _, err := context.InputFile.Seek(context.PDFReader.XrefInformation.StartPos, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to xref table: %w", err)
	}

	// Read the existing xref table
	xrefContent := make([]byte, context.PDFReader.XrefInformation.Length)
	if _, err := context.InputFile.Read(xrefContent); err != nil {
		return 0, fmt.Errorf("failed to read xref table: %w", err)
	}

	// Parse the xref header
	xrefLines := strings.Split(string(xrefContent), "\n")
	xrefHeader := strings.Fields(xrefLines[1])
	if len(xrefHeader) != 2 {
		return 0, fmt.Errorf("invalid xref header format")
	}

	firstObjectID, err := strconv.ParseUint(xrefHeader[0], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid first object ID: %w", err)
	}

	itemCount, err := strconv.ParseUint(xrefHeader[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid item count: %w", err)
	}

	return uint32(firstObjectID + itemCount), nil
}

// writeIncrXrefTable writes the incremental cross-reference table to the output buffer.
func (context *SignContext) writeIncrXrefTable() error {
	// Write xref header
	if _, err := context.OutputBuffer.Write([]byte("xref\n")); err != nil {
		return fmt.Errorf("failed to write incremental xref header: %w", err)
	}

	// Write xref subsection header
	startXrefObj := fmt.Sprintf("%d %d\n", context.lastXrefID+1, len(context.newXrefEntries))
	if _, err := context.OutputBuffer.Write([]byte(startXrefObj)); err != nil {
		return fmt.Errorf("failed to write starting xref object: %w", err)
	}

	// Write new entries
	for _, entry := range context.newXrefEntries {
		xrefLine := fmt.Sprintf("%010d 00000 n\r\n", entry.Offset)
		if _, err := context.OutputBuffer.Write([]byte(xrefLine)); err != nil {
			return fmt.Errorf("failed to write incremental xref entry: %w", err)
		}
	}

	return nil
}

// writeXrefStream writes the cross-reference stream to the output buffer.
func (context *SignContext) writeXrefStream() error {
	buffer := new(bytes.Buffer)

	predictor := context.PDFReader.Trailer().Key("DecodeParms").Key("Predictor").Int64()

	if err := writeXrefStreamEntries(buffer, context); err != nil {
		return fmt.Errorf("failed to write xref stream entries: %w", err)
	}

	streamBytes, err := encodeXrefStream(buffer.Bytes(), predictor)
	if err != nil {
		return fmt.Errorf("failed to encode xref stream: %w", err)
	}

	if err := writeXrefStreamHeader(context, len(streamBytes)); err != nil {
		return fmt.Errorf("failed to write xref stream header: %w", err)
	}

	if err := writeXrefStreamContent(context, streamBytes); err != nil {
		return fmt.Errorf("failed to write xref stream content: %w", err)
	}

	return nil
}

// writeXrefStreamEntries writes the individual entries for the xref stream.
func writeXrefStreamEntries(buffer *bytes.Buffer, context *SignContext) error {
	for _, entry := range context.newXrefEntries {
		writeXrefStreamLine(buffer, 1, int(entry.Offset), 0)
	}

	return nil
}

// encodeXrefStream applies the appropriate encoding to the xref stream.
func encodeXrefStream(data []byte, predictor int64) ([]byte, error) {
	var streamBytes []byte
	var err error

	switch predictor {
	case pngSubPredictor:
		streamBytes, err = EncodePNGSUBBytes(xrefStreamColumns, data)
	case pngUpPredictor:
		streamBytes, err = EncodePNGUPBytes(xrefStreamColumns, data)
	default:
		return nil, fmt.Errorf("unsupported predictor: %d", predictor)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encode xref stream: %w", err)
	}

	return streamBytes, nil
}

// writeXrefStreamHeader writes the header for the xref stream.
func writeXrefStreamHeader(context *SignContext, streamLength int) error {
	newRoot := fmt.Sprintf("Root %d 0 R", context.CatalogData.ObjectId)

	id := context.PDFReader.Trailer().Key("ID")
	id0 := hex.EncodeToString([]byte(id.Index(0).RawString()))
	id1 := hex.EncodeToString([]byte(id.Index(0).RawString()))

	newXref := fmt.Sprintf("%d 0 obj\n<< /Type /XRef /Length %d /Filter /FlateDecode /DecodeParms << /Columns %d /Predictor %d >> /W [ 1 3 1 ] /Prev %d /Size %d /Index [ %d 4 ] /%s /ID [<%s><%s>] >>\n",
		context.SignData.ObjectId+1,
		streamLength,
		xrefStreamColumns,
		xrefStreamPredictor,
		context.PDFReader.XrefInformation.StartPos,
		context.PDFReader.XrefInformation.ItemCount+int64(len(context.newXrefEntries))+1,
		context.PDFReader.XrefInformation.ItemCount,
		newRoot,
		id0,
		id1,
	)

	_, err := io.WriteString(context.OutputBuffer, newXref)
	return err
}

// writeXrefStreamContent writes the content of the xref stream.
func writeXrefStreamContent(context *SignContext, streamBytes []byte) error {
	if _, err := io.WriteString(context.OutputBuffer, "stream\n"); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write(streamBytes); err != nil {
		return err
	}

	if _, err := io.WriteString(context.OutputBuffer, "\nendstream\n"); err != nil {
		return err
	}

	return nil
}

// writeXrefStreamLine writes a single line in the xref stream.
func writeXrefStreamLine(b *bytes.Buffer, xreftype byte, offset int, gen byte) {
	b.WriteByte(xreftype)
	b.Write(encodeInt(offset))
	b.WriteByte(gen)
}

// encodeInt encodes an integer to a 3-byte slice.
func encodeInt(i int) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(i))
	return result[1:4]
}

// EncodePNGSUBBytes encodes data using PNG SUB filter.
func EncodePNGSUBBytes(columns int, data []byte) ([]byte, error) {
	rowCount := len(data) / columns
	if len(data)%columns != 0 {
		return nil, errors.New("invalid row/column length")
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

// EncodePNGUPBytes encodes data using PNG UP filter.
func EncodePNGUPBytes(columns int, data []byte) ([]byte, error) {
	rowCount := len(data) / columns
	if len(data)%columns != 0 {
		return nil, errors.New("invalid row/column length")
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
