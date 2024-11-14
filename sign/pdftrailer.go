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
		new_size := "Size " + strconv.FormatInt(context.PDFReader.XrefInformation.ItemCount+3, 10)

		prev_string := "Prev " + context.PDFReader.Trailer().Key("Prev").String()
		new_prev := "Prev " + strconv.FormatInt(context.PDFReader.XrefInformation.StartPos, 10)

		trailer_string := string(trailer_buf)
		trailer_string = strings.Replace(trailer_string, root_string, new_root, -1)
		trailer_string = strings.Replace(trailer_string, size_string, new_size, -1)
		if strings.Contains(trailer_string, prev_string) {
			trailer_string = strings.Replace(trailer_string, prev_string, new_prev, -1)
		} else {
			trailer_string = strings.Replace(trailer_string, new_root, new_root+"\n  /"+new_prev, -1)
		}

		// Ensure the same amount of padding (two spaces) for each line, except when the line does not start with a whitespace already.
		lines := strings.Split(trailer_string, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, " ") {
				lines[i] = "    " + strings.TrimSpace(line)
			}
		}
		trailer_string = strings.Join(lines, "\n")

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
	if _, err := context.OutputBuffer.Write([]byte("%%EOF\n")); err != nil {
		return err
	}

	return nil
}
