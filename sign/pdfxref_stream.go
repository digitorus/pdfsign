package sign

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	xrefStreamColumns   = 6 // Column width (1+4+1)
	xrefStreamPredictor = 12
	defaultPredictor    = 1  // No prediction (the default value)
	pngSubPredictor     = 11 // PNG prediction (on encoding, PNG Sub on all rows)
	pngUpPredictor      = 12 // PNG prediction (on encoding, PNG Up on all rows)
)

// writeXrefStream writes the cross-reference stream to the output buffer.
func (context *SignContext) writeXrefStream() error {
	var buffer bytes.Buffer

	predictor := context.PDFReader.Trailer().Key("DecodeParms").Key("Predictor").Int64()
	if predictor == 0 {
		predictor = xrefStreamPredictor
	}

	if err := writeXrefStreamEntries(&buffer, context); err != nil {
		return fmt.Errorf("failed to write xref stream entries: %w", err)
	}

	streamBytes, err := encodeXrefStream(buffer.Bytes(), predictor)
	if err != nil {
		return fmt.Errorf("failed to encode xref stream: %w", err)
	}

	var xrefStreamObject bytes.Buffer

	if err := writeXrefStreamHeader(&xrefStreamObject, context, len(streamBytes)); err != nil {
		return fmt.Errorf("failed to write xref stream header: %w", err)
	}

	if err := writeXrefStreamContent(&xrefStreamObject, streamBytes); err != nil {
		return fmt.Errorf("failed to write xref stream content: %w", err)
	}

	_, err = context.addObject(xrefStreamObject.Bytes())
	if err != nil {
		return fmt.Errorf("failed to add xref stream object: %w", err)
	}

	return nil
}

// writeXrefStreamEntries writes the individual entries for the xref stream.
func writeXrefStreamEntries(buffer *bytes.Buffer, context *SignContext) error {
	// Write updated entries first
	for _, entry := range context.updatedXrefEntries {
		writeXrefStreamLine(buffer, 1, int(entry.Offset), 0)
	}

	// Write new entries
	for _, entry := range context.newXrefEntries {
		writeXrefStreamLine(buffer, 1, int(entry.Offset), 0)
	}

	return nil
}

// encodeXrefStream applies the appropriate encoding to the xref stream.
func encodeXrefStream(data []byte, predictor int64) ([]byte, error) {
	// Use FlateDecode without prediction for xref streams
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeXrefStreamHeader writes the header for the xref stream.
func writeXrefStreamHeader(buffer *bytes.Buffer, context *SignContext, streamLength int) error {
	id := context.PDFReader.Trailer().Key("ID")

	// Calculate total entries and create index array
	totalEntries := uint32(context.PDFReader.XrefInformation.ItemCount)
	var indexArray []uint32

	// Add existing entries section
	if len(context.updatedXrefEntries) > 0 {
		for _, entry := range context.updatedXrefEntries {
			indexArray = append(indexArray, entry.ID, 1)
		}
	}

	// Add new entries section
	if len(context.newXrefEntries) > 0 {
		indexArray = append(indexArray, context.lastXrefID+1, uint32(len(context.newXrefEntries)))
		totalEntries += uint32(len(context.newXrefEntries))
	}

	buffer.WriteString("<< /Type /XRef\n")
	fmt.Fprintf(buffer, "  /Length %d\n", streamLength)
	buffer.WriteString("  /Filter /FlateDecode\n")
	// Change W array to [1 4 1] to accommodate larger offsets
	buffer.WriteString("  /W [ 1 4 1 ]\n")
	fmt.Fprintf(buffer, "  /Prev %d\n", context.PDFReader.XrefInformation.StartPos)
	fmt.Fprintf(buffer, "  /Size %d\n", totalEntries+1)

	// Write index array if we have entries
	if len(indexArray) > 0 {
		buffer.WriteString("  /Index [")
		for _, idx := range indexArray {
			fmt.Fprintf(buffer, " %d", idx)
		}
		buffer.WriteString(" ]\n")
	}

	fmt.Fprintf(buffer, "  /Root %d 0 R\n", context.CatalogData.ObjectId)

	if !id.IsNull() {
		id0 := hex.EncodeToString([]byte(id.Index(0).RawString()))
		id1 := hex.EncodeToString([]byte(id.Index(1).RawString()))
		fmt.Fprintf(buffer, "  /ID [<%s><%s>]\n", id0, id1)
	}

	buffer.WriteString(">>\n")
	return nil
}

// writeXrefStreamContent writes the content of the xref stream.
func writeXrefStreamContent(buffer *bytes.Buffer, streamBytes []byte) error {
	if _, err := io.WriteString(buffer, "stream\n"); err != nil {
		return err
	}

	if _, err := buffer.Write(streamBytes); err != nil {
		return err
	}

	if _, err := io.WriteString(buffer, "\nendstream\n"); err != nil {
		return err
	}

	return nil
}

// writeXrefStreamLine writes a single line in the xref stream.
func writeXrefStreamLine(b *bytes.Buffer, xreftype byte, offset int, gen byte) {
	// Write type (1 byte)
	b.WriteByte(xreftype)

	// Write offset (4 bytes)
	offsetBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(offsetBytes, uint32(offset))
	b.Write(offsetBytes)

	// Write generation (1 byte)
	b.WriteByte(gen)
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
	if err := w.Close(); err != nil {
		return nil, err
	}

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
	if err := w.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
