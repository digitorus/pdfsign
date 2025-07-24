package sign

import (
	"bufio"
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdf"
)

func TestFindFirstPage(t *testing.T) {
	input_file, reader := loadHelpersTestPDF()
	if input_file == nil || reader == nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	root := reader.Trailer().Key("Root")
	root_keys := root.Keys()
	found_pages := false
	for _, key := range root_keys {
		if key == "Pages" {
			found_pages = true
			break
		}
	}

	if !found_pages {
		if err := input_file.Close(); err != nil {
			t.Errorf("Failed to close input_file: %v", err)
		}
		t.Errorf("Could not find pages element")
		return
	}

	first_page, err := findFirstPage(root.Key("Pages"))
	if err != nil {
		if err := input_file.Close(); err != nil {
			t.Errorf("Failed to close input_file: %v", err)
		}
		t.Errorf("Could not find first page")
		return
	}

	first_page_ptr := first_page.GetPtr()
	if first_page_ptr.GetGen() != 0 {
		if err := input_file.Close(); err != nil {
			t.Errorf("Failed to close input_file: %v", err)
		}
		t.Errorf("First page gen mismatch")
	}

	if first_page_ptr.GetID() != 4 {
		t.Errorf("First page ID mismatch")
	}

	if err := input_file.Close(); err != nil {
		t.Errorf("Failed to close input_file: %v", err)
	}
}

func TestPDFString(t *testing.T) {
	string_compare := map[string]string{
		"Test":    "(Test)",
		"((Test)": "(\\(\\(Test\\))",
		"\\TEst":  "(\\\\TEst)",
		"\rnew":   "(\\rnew)",
	}

	for text, expected := range string_compare {
		if pdfString(text) != expected {
			t.Errorf("Error while escaping %s. Expected %s, got %s.", text, expected, pdfString(text))
		}
	}
}

func TestPdfDateTime(t *testing.T) {
	timezone, _ := time.LoadLocation("Europe/Tallinn")
	timezone_1, _ := time.LoadLocation("Africa/Casablanca")
	timezone_2, _ := time.LoadLocation("America/New_York")
	timezone_3, _ := time.LoadLocation("Asia/Jerusalem")
	timezone_4, _ := time.LoadLocation("Europe/Amsterdam")
	timezone_5, _ := time.LoadLocation("Pacific/Honolulu")

	now := time.Date(2017, 9, 23, 14, 39, 0, 0, timezone)

	date_compare := map[time.Time]string{
		now.In(timezone_1): "(D:20170923123900+01'00')",
		now.In(timezone_2): "(D:20170923073900-04'00')",
		now.In(timezone_3): "(D:20170923143900+03'00')",
		now.In(timezone_4): "(D:20170923133900+02'00')",
		now.In(timezone_5): "(D:20170923013900-10'00')",
	}

	for date, expected := range date_compare {
		if pdfDateTime(date) != expected {
			t.Errorf("Error while converting date %s to string. Expected %s, got %s.", date.String(), expected, pdfDateTime(date))
		}
	}
}

func TestLeftPad(t *testing.T) {
	string_compare := map[string]string{
		"123456789": "123456789",
		"12345678":  "12345678",
		"1234567":   "_1234567",
		"123456":    "__123456",
		"12345":     "___12345",
		"1234":      "____1234",
		"123":       "_____123",
		"12":        "______12",
		"1":         "_______1",
		"":          "________",
	}

	for text, expected := range string_compare {
		if leftPad(text, "_", 8-len(text)) != expected {
			t.Errorf("Error while left padding %s. Expected %s, got %s.", text, expected, leftPad(text, "_", 8-len(text)))
		}
	}
}

func TestWritePartFromSourceFileToTargetFile(t *testing.T) {
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)

	input_file, err := os.Open("../testfiles/testfile20.pdf")
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	_ = writePartFromSourceFileToTargetFile(input_file, writer, 0, 0)
	if err := writer.Flush(); err != nil {
		t.Errorf("Failed to flush writer: %v", err)
	}

	if writer.Buffered() != 0 {
		t.Errorf("Content was copied while length was 0")
	}

	_ = writePartFromSourceFileToTargetFile(input_file, writer, 0, -20)
	if err := writer.Flush(); err != nil {
		t.Errorf("Failed to flush writer: %v", err)
	}

	if writer.Buffered() != 0 {
		t.Errorf("Content was copied while length was smaller than 0")
	}

	_ = writePartFromSourceFileToTargetFile(input_file, writer, 0, 8)
	if err := writer.Flush(); err != nil {
		t.Errorf("Failed to flush writer: %v", err)
	}

	if b.String() != "%PDF-2.0" {
		t.Errorf("Wrong content was copied, got %s but expected %s", b.String(), "%PDF-2.0")
	}

	_ = writePartFromSourceFileToTargetFile(input_file, writer, 33, 8)
	if err := writer.Flush(); err != nil {
		t.Errorf("Failed to flush writer: %v", err)
	}

	if b.String() != "%PDF-2.0/Catalog" {
		t.Errorf("Wrong content was copied, got %s but expected %s", b.String(), "%PDF-2.0/Catalog")
	}

	_ = writePartFromSourceFileToTargetFile(input_file, writer, 0, 1200)

	if writer.Buffered() != 1200 {
		t.Errorf("Requested 1200 bytes but only got %d", writer.Buffered())
	}

	if err := input_file.Close(); err != nil {
		t.Errorf("Failed to close input_file: %v", err)
	}
}

func loadHelpersTestPDF() (*os.File, *pdf.Reader) {
	input_file, err := os.Open("../testfiles/testfile20.pdf")
	if err != nil {
		_ = input_file.Close()
		return nil, nil
	}

	finfo, err := input_file.Stat()
	if err != nil {
		_ = input_file.Close()
		return nil, nil
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		_ = input_file.Close()
		return nil, nil
	}

	return input_file, rdr
}
