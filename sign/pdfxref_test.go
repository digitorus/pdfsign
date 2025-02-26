package sign

import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
	"github.com/mattetti/filebuffer"
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
			st.Parallel()

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

func TestWriteXrefStreamLine(t *testing.T) {
	tests := []struct {
		name     string
		xreftype byte
		offset   int
		gen      byte
		expected []byte
	}{
		{
			name:     "basic entry",
			xreftype: 1,
			offset:   1234,
			gen:      0,
			expected: []byte{1, 0, 0, 4, 210, 0},
		},
		{
			name:     "zero entry",
			xreftype: 0,
			offset:   0,
			gen:      0,
			expected: []byte{0, 0, 0, 0, 0, 0},
		},
		{
			name:     "max offset",
			xreftype: 1,
			offset:   16777215, // 2^24 - 1
			gen:      255,
			expected: []byte{1, 0, 255, 255, 255, 255},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeXrefStreamLine(&buf, tt.xreftype, tt.offset, tt.gen)
			result := buf.Bytes()
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("writeXrefStreamLine() = %v, want %v", result, tt.expected)
				t.Errorf("hex: got %x, want %x", result, tt.expected)
			}
			if len(result) != xrefStreamColumns {
				t.Errorf("incorrect length: got %d bytes, want %d bytes", len(result), xrefStreamColumns)
			}
		})
	}
}

func TestEncodePNGSUBBytes(t *testing.T) {
	tests := []struct {
		name     string
		columns  int
		input    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "valid encoding",
			columns:  3,
			input:    []byte{10, 20, 30, 40, 50, 60},
			expected: []byte{1, 10, 10, 10, 1, 40, 10, 10},
			wantErr:  false,
		},
		{
			name:    "invalid columns",
			columns: 4,
			input:   []byte{1, 2, 3, 4, 5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePNGSUBBytes(tt.columns, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePNGSUBBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Error("EncodePNGSUBBytes() returned nil for valid input")
				}
				// Decompress the result
				r, err := zlib.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Fatalf("Failed to create zlib reader: %v", err)
				}
				defer r.Close()

				decompressed, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("Failed to decompress: %v", err)
				}

				if !bytes.Equal(decompressed, tt.expected) {
					t.Errorf("EncodePNGSUBBytes() = %v, want %v", decompressed, tt.expected)
				}
			}
		})
	}
}

func TestEncodePNGUPBytes(t *testing.T) {
	tests := []struct {
		name     string
		columns  int
		input    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "valid encoding",
			columns:  3,
			input:    []byte{10, 20, 30, 40, 50, 60},
			expected: []byte{2, 10, 20, 30, 2, 30, 30, 30},
			wantErr:  false,
		},
		{
			name:    "invalid columns",
			columns: 4,
			input:   []byte{1, 2, 3, 4, 5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePNGUPBytes(tt.columns, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePNGUPBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Error("EncodePNGUPBytes() returned nil for valid input")
				}
				// Decompress the result
				r, err := zlib.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Fatalf("Failed to create zlib reader: %v", err)
				}
				defer r.Close()

				decompressed, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("Failed to decompress: %v", err)
				}

				if !bytes.Equal(decompressed, tt.expected) {
					t.Errorf("EncodePNGUPBytes() = %v, want %v", decompressed, tt.expected)
				}
			}
		})
	}
}

func TestWriteXrefStream(t *testing.T) {
	input_file, err := os.Open("../testfiles/testfile12.pdf")
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer input_file.Close()

	finfo, err := input_file.Stat()
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	r, err := pdf.NewReader(input_file, finfo.Size())
	if err != nil {
		t.Fatalf("Failed to create PDF reader: %v", err)
	}

	outputBuf := &filebuffer.Buffer{
		Buff: new(bytes.Buffer),
	}
	context := &SignContext{
		InputFile:    input_file,
		PDFReader:    r,
		OutputBuffer: outputBuf,
		newXrefEntries: []xrefEntry{
			{ID: 1, Offset: 100},
		},
	}

	err = context.writeXrefStream()
	if err != nil {
		t.Errorf("writeXrefStream() error = %v", err)
	}

	// Check if output contains required xref stream elements
	output := outputBuf.Buff.String()
	requiredElements := []string{
		"/Type /XRef",
		"/Filter /FlateDecode",
		"/W [ 1 4 1 ]",
		"stream\n",
		"endstream",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(output, elem) {
			t.Errorf("Output missing required element: %s", elem)
		}
	}
}

func TestAddObject(t *testing.T) {
	outputBuf := &filebuffer.Buffer{
		Buff: new(bytes.Buffer),
	}
	context := &SignContext{
		OutputBuffer: outputBuf,
		lastXrefID:   10,
	}

	tests := []struct {
		name         string
		object       []byte
		expectedID   uint32
		expectedText string
		wantErr      bool
	}{
		{
			name:         "valid object",
			object:       []byte("test object"),
			expectedID:   11,
			expectedText: "11 0 obj\ntest object\nendobj\n",
			wantErr:      false,
		},
		{
			name:         "object with whitespace",
			object:       []byte("  test object  "),
			expectedID:   12,
			expectedText: "12 0 obj\ntest object\nendobj\n",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputBuf.Buff.Reset()
			id, err := context.addObject(tt.object)
			if (err != nil) != tt.wantErr {
				t.Errorf("addObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if id != tt.expectedID {
				t.Errorf("addObject() got ID = %v, want %v", id, tt.expectedID)
			}

			got := outputBuf.Buff.String()
			if !strings.Contains(got, tt.expectedText) {
				t.Errorf("addObject() output = %q, want to contain %q", got, tt.expectedText)
			}

			// Check xref entry
			if len(context.newXrefEntries) == 0 {
				t.Error("No xref entry added")
			} else {
				lastEntry := context.newXrefEntries[len(context.newXrefEntries)-1]
				if lastEntry.ID != tt.expectedID {
					t.Errorf("xref entry ID = %v, want %v", lastEntry.ID, tt.expectedID)
				}
			}
		})
	}
}
