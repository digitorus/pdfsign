package extract

import (
	"errors"
	"io"
	"iter"

	pdflib "github.com/digitorus/pdf"
)

// Signature represents a signature dictionary in the PDF.
type Signature struct {
	Obj  pdflib.Value
	File io.ReaderAt
}

// Object returns the underlying low-level PDF value for the signature dictionary.
func (s *Signature) Object() pdflib.Value {
	return s.Obj
}

// Name returns the name of the person or authority signing the document.
func (s *Signature) Name() string {
	return s.Obj.Key("Name").Text()
}

// Filter returns the name of the preferred signature handler.
func (s *Signature) Filter() string {
	return s.Obj.Key("Filter").Name()
}

// SubFilter returns the encoding format of the signature.
func (s *Signature) SubFilter() string {
	return s.Obj.Key("SubFilter").Name()
}

// Contents returns the raw PKCS#7/CMS signature envelope.
func (s *Signature) Contents() []byte {
	return []byte(s.Obj.Key("Contents").RawString())
}

// ByteRange returns the array of byte offsets that define the range(s) of the file covered by the signature.
func (s *Signature) ByteRange() []int64 {
	br := s.Obj.Key("ByteRange")
	if br.IsNull() || br.Len() == 0 {
		return nil
	}

	ranges := make([]int64, 0, br.Len())
	for i := 0; i < br.Len(); i++ {
		ranges = append(ranges, br.Index(i).Int64())
	}
	return ranges
}

// SignedData returns a reader that provides the actual bytes of the document covered by the signature.
func (s *Signature) SignedData() (io.Reader, error) {
	ranges := s.ByteRange()
	if len(ranges) == 0 || len(ranges)%2 != 0 {
		return nil, errors.New("invalid or missing ByteRange")
	}

	return &ByteRangeReader{
		File:   s.File,
		Ranges: ranges,
	}, nil
}

// Iter returns an iterator over all signature dictionaries in the PDF reader.
func Iter(rdr *pdflib.Reader, file io.ReaderAt) iter.Seq2[*Signature, error] {
	return func(yield func(*Signature, error) bool) {
		root := rdr.Trailer().Key("Root")
		acroForm := root.Key("AcroForm")

		sigFlags := acroForm.Key("SigFlags")
		if sigFlags.IsNull() {
			return
		}

		fields := acroForm.Key("Fields")

		var traverse func(pdflib.Value) bool
		traverse = func(arr pdflib.Value) bool {
			if !arr.IsNull() && arr.Kind() == pdflib.Array {
				for i := 0; i < arr.Len(); i++ {
					field := arr.Index(i)

					if field.Key("FT").Name() == "Sig" {
						v := field.Key("V")
						isSig := false
						sigType := v.Key("Type").Name()
						if sigType == "Sig" || sigType == "DocTimeStamp" {
							isSig = true
						} else if !v.Key("Filter").IsNull() && !v.Key("Contents").IsNull() {
							isSig = true
						}

						if isSig {
							sig := &Signature{
								Obj:  v,
								File: file,
							}
							if !yield(sig, nil) {
								return false
							}
						}
					}

					kids := field.Key("Kids")
					if !kids.IsNull() {
						if !traverse(kids) {
							return false
						}
					}
				}
			}
			return true
		}

		traverse(fields)
	}
}

// ByteRangeReader implements io.Reader to look like a continuous stream
// over the non-contiguous byte ranges.
type ByteRangeReader struct {
	File      io.ReaderAt
	Ranges    []int64
	rangeIdx  int
	readInCur int64
}

func (r *ByteRangeReader) Read(p []byte) (n int, err error) {
	if r.rangeIdx >= len(r.Ranges) {
		return 0, io.EOF
	}

	totalRead := 0
	for totalRead < len(p) && r.rangeIdx < len(r.Ranges) {
		start := r.Ranges[r.rangeIdx]
		length := r.Ranges[r.rangeIdx+1]

		remainingInCurrent := length - r.readInCur
		if remainingInCurrent <= 0 {
			r.rangeIdx += 2
			r.readInCur = 0
			continue
		}

		toRead := int64(len(p) - totalRead)
		if toRead > remainingInCurrent {
			toRead = remainingInCurrent
		}

		bytesRead, readErr := r.File.ReadAt(p[totalRead:totalRead+int(toRead)], start+r.readInCur)
		if bytesRead > 0 {
			totalRead += bytesRead
			r.readInCur += int64(bytesRead)
		}

		if readErr != nil {
			if readErr == io.EOF && r.readInCur == length {
				r.rangeIdx += 2
				r.readInCur = 0
				continue
			}
			return totalRead, readErr
		}
	}

	if totalRead == 0 && r.rangeIdx >= len(r.Ranges) {
		return 0, io.EOF
	}

	return totalRead, nil
}
