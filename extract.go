package pdfsign

import (
	"fmt"
	"iter"

	pdflib "github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/extract"
)

// Signatures returns an iterator over all signature dictionaries in the document.
func (d *Document) Signatures() iter.Seq2[*Signature, error] {
	return func(yield func(*Signature, error) bool) {
		rdr := d.rdr
		if rdr == nil {
			var err error
			rdr, err = pdflib.NewReader(d.reader, d.size)
			if err != nil {
				yield(nil, fmt.Errorf("failed to create reader: %w", err))
				return
			}
		}

		for sig, err := range extract.Iter(rdr, d.reader) {
			if !yield(sig, err) {
				return
			}
		}
	}
}
