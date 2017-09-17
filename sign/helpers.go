package sign

import (
	"bitbucket.org/digitorus/pdf"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

func findFirstPage(parent pdf.Value) (pdf.Value, error) {
	value_type := parent.Key("Type").String()
	if value_type == "/Pages" {

		for i := 0; i < parent.Key("Kids").Len(); i++ {
			recurse_parent, recurse_err := findFirstPage(parent.Key("Kids").Index(i))
			if recurse_err == nil {
				return recurse_parent, recurse_err
			}
		}

		return parent, errors.New("Could not find first page.")
	}

	if value_type == "/Page" {
		return parent, nil
	}

	return parent, errors.New("Could not find first page.")
}

func pdfString(text string) string {
	text = strings.Replace(text, "\\", "\\\\", -1)
	text = strings.Replace(text, ")", "\\)", -1)
	text = strings.Replace(text, "(", "\\(", -1)
	text = strings.Replace(text, "\r", "\\r", -1)

	text = "(" + text + ")"

	return text
}

func pdfDateTime(date time.Time) string {
	// Calculate timezone offset from GMT.
	_, original_offset := date.Zone()
	offset := original_offset
	if offset < 0 {
		offset = (offset - offset) - offset
	}

	offset_duration := time.Duration(offset) * time.Second
	offset_hours := int(math.Floor(offset_duration.Hours()))
	offset_minutes := int(math.Floor(offset_duration.Minutes()))
	offset_minutes = offset_minutes - (offset_hours * 60)

	dateString := "D:" + date.Format("20060102150405")

	// Do some special formatting as the PDF timezone format isn't supported by Go.
	if original_offset < 0 {
		dateString += "-"
	} else {
		dateString += "+"
	}

	offset_hours_formatted := fmt.Sprintf("%d", offset_hours)
	offset_minutes_formatted := fmt.Sprintf("%d", offset_minutes)
	dateString += leftPad(offset_hours_formatted, "0", 2-len(offset_hours_formatted)) + "'" + leftPad(offset_minutes_formatted, "0", 2-len(offset_minutes_formatted)) + "'"

	return pdfString(dateString)
}

func leftPad(s string, padStr string, pLen int) string {
	return strings.Repeat(padStr, pLen) + s
}

func writePartFromSourceFileToTargetFile(input_file *os.File, output_file *os.File, offset int64, length int64) error {
	input_file.Seek(offset, 0)

	// Create a small buffer for proper IO handling.
	max_chunk_length := int64(1024)

	// If the target length is smaller than our chunk size, use that as chunk size.
	if length < max_chunk_length {
		max_chunk_length = length
	}

	// Track read/written bytes so we know when we're done.
	read_bytes := int64(0)

	if length <= 0 {
		return nil
	}

	// Create a buffer for the chunks.
	buf := make([]byte, max_chunk_length)
	for {
		// Read the chunk from the input file.
		n, err := input_file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// If we got to the end of the file, break.
		if err == io.EOF {
			break
		}

		// If nothing was read, break.
		if n == 0 {
			break
		}

		// Write the chunk to the output file.
		if _, err := output_file.Write(buf[:n]); err != nil {
			return err
		}

		read_bytes += int64(n)

		// If we read enough bytes, break.
		if read_bytes >= length {
			break
		}

		// If our next chunk will be too big, make a smaller buffer.
		// If we won't do this, we might end up with more data than we want.
		if length-read_bytes < max_chunk_length {
			buf = make([]byte, length-read_bytes)
		}
	}

	return nil
}
