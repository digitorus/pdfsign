package sign

import (
	"strconv"
	"strings"
)

func (context *SignContext) writeTrailer() error {

	if context.PDFReader.XrefInformation.Type == "table" {
		trailer_length := context.PDFReader.XrefInformation.IncludingTrailerEndPos - context.PDFReader.XrefInformation.EndPos

		// Read the trailer so we can replace the size.
		if _, err := context.InputFile.Seek(context.PDFReader.XrefInformation.EndPos+1, 0); err != nil {
			return err
		}
		trailer_buf := make([]byte, trailer_length)
		if _, err := context.InputFile.Read(trailer_buf); err != nil {
			return err
		}

		root_string := "Root " + context.CatalogData.RootString
		new_root := "Root " + strconv.FormatInt(int64(context.CatalogData.ObjectId), 10) + " 0 R"

		size_string := "Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount, 10)
		new_size := "Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+4, 10)

		info := context.PDFReader.Trailer().Key("Info")
		infoPtr := info.GetPtr()

		info_string := "Info " + strconv.Itoa(int(infoPtr.GetID())) + " " + strconv.Itoa(int(infoPtr.GetGen())) + " R"
		new_info := "Info " + strconv.FormatInt(int64(context.InfoData.ObjectId), 10) + " 0 R"

		trailer_string := string(trailer_buf)
		trailer_string = strings.Replace(trailer_string, root_string, new_root, -1)
		trailer_string = strings.Replace(trailer_string, size_string, new_size, -1)
		trailer_string = strings.Replace(trailer_string, info_string, new_info, -1)

		// Write the new trailer.
		if _, err := context.OutputBuffer.Write([]byte(trailer_string)); err != nil {
			return err
		}
	}

	// Write the new xref start position.
	if _, err := context.OutputBuffer.Write([]byte(strconv.FormatInt(context.NewXrefStart, 10) + "\n")); err != nil {
		return err
	}

	// Write PDF ending.
	if _, err := context.OutputBuffer.Write([]byte("%%EOF")); err != nil {
		return err
	}

	return nil
}
