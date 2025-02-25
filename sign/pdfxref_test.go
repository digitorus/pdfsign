package sign

import (
	"os"
	"testing"

	"github.com/digitorus/pdf"
)

func TestGetLastObjectIDFromXref(t *testing.T) {
	testCases := []struct {
		fileName string
		expected uint32
	}{
		{"testfile12.pdf", 16},
		{"testfile14.pdf", 15},
		{"testfile16.pdf", 567},
		{"testfile17.pdf", 20},
		{"testfile20.pdf", 10},
		{"testfile21.pdf", 16},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(st *testing.T) {
			//st.Parallel()

			input_file, err := os.Open("../testfiles/" + tc.fileName)
			if err != nil {
				st.Fatalf("%s: %s", tc.fileName, err.Error())
			}
			defer input_file.Close()

			finfo, err := input_file.Stat()
			if err != nil {
				st.Fatalf("%s: %s", tc.fileName, err.Error())
			}
			size := finfo.Size()

			r, err := pdf.NewReader(input_file, size)
			if err != nil {
				st.Fatalf("%s: %s", tc.fileName, err.Error())
			}

			sc := &SignContext{
				InputFile: input_file,
				PDFReader: r,
			}
			obj, err := sc.getLastObjectIDFromXref()
			if err != nil {
				st.Fatalf("%s: %s", tc.fileName, err.Error())
			}
			if obj != tc.expected {
				st.Fatalf("%s: expected object id %d, got %d", tc.fileName, tc.expected, obj)
			}
		})
	}
}
