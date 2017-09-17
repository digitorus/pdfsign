package sign

import (
	"testing"
	"io/ioutil"
	"fmt"
	"os"
	"path/filepath"

	"bitbucket.org/digitorus/pdf"
)

func TestReaderCanReadPDF(t *testing.T) {
	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			fmt.Printf("Skipping file %s", f.Name())
			continue
		}

		input_file, err := os.Open("../testfiles/" + f.Name())
		if err != nil {
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}

		finfo, err := input_file.Stat()
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}
		size := finfo.Size()

		_, err = pdf.NewReader(input_file, size)
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}
	}
}

func TestSignPDF(t *testing.T) {
	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			fmt.Printf("Skipping file %s", f.Name())
			continue
		}

		input_file, err := os.Open("../testfiles/" + f.Name())
		if err != nil {
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}

		finfo, err := input_file.Stat()
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}
		size := finfo.Size()

		_, err = pdf.NewReader(input_file, size)
		if err != nil {
			input_file.Close()
			t.Errorf("%s: %s", f.Name(), err.Error())
			return
		}

		// @todo: implement signer.
	}
}