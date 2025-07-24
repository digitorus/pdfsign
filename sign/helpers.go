package sign

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/digitorus/pdf"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func findFirstPage(parent pdf.Value) (pdf.Value, error) {
	value_type := parent.Key("Type").String()
	if value_type == "/Pages" {
		for i := 0; i < parent.Key("Kids").Len(); i++ {
			kid := parent.Key("Kids").Index(i)
			recurse_parent, recurse_err := findFirstPage(kid)
			if recurse_err == nil {
				return recurse_parent, recurse_err
			}
		}

		return parent, errors.New("could not find first page")
	}

	if value_type == "/Page" {
		return parent, nil
	}

	return parent, errors.New("could not find first page")
}

func pdfString(text string) string {
	if !isASCII(text) {
		// UTF-16BE
		enc := unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewEncoder()
		res, _, err := transform.String(enc, text)
		if err != nil {
			panic(err)
		}
		return "(" + res + ")"
	}

	// UTF-8
	// (\357\273\277Layer 1)               % UTF-8 Layer 1 Name
	// <EF BB BF DA AF DA 86 D9 BE DA 98>  % UTF-8 Layer 2 Name
	// text = "\357\273\277" + text
	// text = hex.EncodeToString([]byte(text))
	// text = "<" + text + ">"

	// PDFDocEncoded
	text = strings.ReplaceAll(text, "\\", "\\\\")
	text = strings.ReplaceAll(text, ")", "\\)")
	text = strings.ReplaceAll(text, "(", "\\(")
	text = strings.ReplaceAll(text, "\r", "\\r")
	text = "(" + text + ")"

	return text
}

func pdfDateTime(date time.Time) string {
	// Calculate timezone offset from GMT.
	_, original_offset := date.Zone()
	offset := original_offset
	if offset < 0 {
		offset = -offset
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
	if pLen <= 0 {
		return s
	}
	return strings.Repeat(padStr, pLen) + s
}

func writePartFromSourceFileToTargetFile(input_file io.ReadSeeker, output_file io.Writer, offset int64, length int64) error {
	_, err := input_file.Seek(offset, 0)
	if err != nil {
		return err
	}

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

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

// func getHashAlgorithmFromOID(target asn1.ObjectIdentifier) crypto.Hash {
// 	for hash, oid := range hashOIDs {
// 		if oid.Equal(target) {
// 			return hash
// 		}
// 	}
// 	return crypto.Hash(0)
// }

func getOIDFromHashAlgorithm(target crypto.Hash) asn1.ObjectIdentifier {
	for hash, oid := range hashOIDs {
		if hash == target {
			return oid
		}
	}
	return nil
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > '\u007F' {
			return false
		}
	}
	return true
}
