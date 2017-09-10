package sign

import (
	"errors"
	"strconv"
	"encoding/hex"
	"compress/zlib"
	"bytes"
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
	// @todo: DO NOT FORGET TO ADD SELF REFERENCE!!!
	// @todo: fix format (columns) for stream
	// @todo: add PNG-Up support.
	var streamBytes bytes.Buffer
	w := zlib.NewWriter(&streamBytes)

	// Create the new catalog xref line.
	visual_signature_object_start_position := strconv.FormatInt(context.Filesize, 10)
	visual_signature_xref_line := leftPad(visual_signature_object_start_position, "0", 10-len(visual_signature_object_start_position)) + " 00000 n \n"

	// Write the new catalog xref line.
	if _, err := w.Write([]byte(visual_signature_xref_line)); err != nil {
		return err
	}

	// Create the new catalog xref line.
	catalog_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length, 10)
	catalog_xref_line := leftPad(catalog_object_start_position, "0", 10-len(catalog_object_start_position)) + " 00000 n \n"

	// Write the new catalog xref line.
	if _, err := w.Write([]byte(catalog_xref_line)); err != nil {
		return err
	}

	// Create the new signature xref line.
	info_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length, 10)
	info_xref_line := leftPad(info_object_start_position, "0", 10-len(info_object_start_position)) + " 00000 n \n"

	// Write the new signature xref line.
	if _, err := w.Write([]byte(info_xref_line)); err != nil {
		return err
	}

	// Create the new signature xref line.
	signature_object_start_position := strconv.FormatInt(context.Filesize+context.VisualSignData.Length+context.CatalogData.Length+context.InfoData.Length, 10)
	signature_xref_line := leftPad(signature_object_start_position, "0", 10-len(signature_object_start_position)) + " 00000 n \n"

	// Write the new signature xref line.
	if _, err := w.Write([]byte(signature_xref_line)); err != nil {
		return err
	}
	w.Close()

	new_info := "Info " + strconv.FormatInt(int64(context.InfoData.ObjectId), 10) + " 0 R"
	new_root := "Root " + strconv.FormatInt(int64(context.CatalogData.ObjectId), 10) + " 0 R"

	id := context.PDFReader.Trailer().Key("ID")

	id0 := hex.EncodeToString([]byte(id.Index(0).RawString()))
	id1 := hex.EncodeToString([]byte(id.Index(0).RawString()))

	new_xref := strconv.Itoa(int(context.SignData.ObjectId + 1)) + " 0 obj\n"
	new_xref += "<< /Type /XRef /Length " + strconv.Itoa(len(streamBytes.Bytes()))  + " /Filter /FlateDecode /DecodeParms << /Columns 5 /Predictor 12 >> /W [ 1 3 1 ] /Prev " +  strconv.FormatInt(context.PDFReader.XrefInformation.StartPos, 10) + " /Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+5, 10) + " /Index [ " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount, 10) + " 5 ] /" + new_info + " /" + new_root + " /ID [<" + id0 + "><" + id1 + ">] >>\n"
	if _, err := context.OutputFile.Write([]byte(new_xref)); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write([]byte("stream\n")); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write(streamBytes.Bytes()); err != nil {
		return err
	}

	if _, err := context.OutputFile.Write([]byte("\nendstream\n")); err != nil {
		return err
	}

	return nil
}
