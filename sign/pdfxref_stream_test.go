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
				defer func() {
					if cerr := r.Close(); cerr != nil {
						t.Errorf("Failed to close zlib reader: %v", cerr)
					}
				}()

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
				defer func() {
					if cerr := r.Close(); cerr != nil {
						t.Errorf("Failed to close zlib reader: %v", cerr)
					}
				}()

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
	defer func() {
		if err := input_file.Close(); err != nil {
			t.Errorf("Failed to close input_file: %v", err)
		}
	}()

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
