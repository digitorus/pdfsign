// Package pdfsign provides tools for signing and verifying PDF documents.
// It supports PAdES, C2PA, and JAdES signature formats with
// configurable visual appearances, form filling, and PDF/A compliance.
//
// Basic usage:
//
//	doc, err := pdf.OpenFile("document.pdf")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	doc.Sign(signer, cert).
//	    Reason("Approved").
//	    Location("Amsterdam")
//
//	result, err := doc.Write(output)
//
// See https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/ for PAdES specification.
package pdfsign

import (
	"compress/zlib"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	pdflib "github.com/digitorus/pdf"
)

// Document represents a PDF document that can be signed, verified, or modified.
type Document struct {
	reader io.ReaderAt
	size   int64
	rdr    *pdflib.Reader

	// Registered resources
	fonts  map[string]*Font
	images map[string]*Image

	// Staged operations
	pendingSigns    []*SignBuilder
	pendingInitials *InitialsConfig
	pendingFields   map[string]any

	// Document settings
	compliance    Compliance
	compressLevel int
	unit          float64
}

// Open initializes a PDF Document from an io.ReaderAt (e.g., an open file or memory buffer).
// The size parameter must be the total size of the PDF in bytes.
func Open(reader io.ReaderAt, size int64) (*Document, error) {
	rdr, err := pdflib.NewReader(reader, size)
	if err != nil {
		return nil, fmt.Errorf("failed to open PDF: %w", err)
	}
	doc := &Document{
		reader:        reader,
		size:          size,
		rdr:           rdr,
		fonts:         make(map[string]*Font),
		images:        make(map[string]*Image),
		pendingFields: make(map[string]any),
		compressLevel: zlib.DefaultCompression,
		unit:          1.0, // Default to PDF points
	}

	// Attempt to scan existing fonts for deduplication
	// We ignore errors here as it's an optimization
	_ = doc.scanExistingFonts()

	return doc, nil
}

// OpenFile is a convenience method to initialize a PDF Document from a file on disk.
func OpenFile(path string) (*Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	finfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return Open(file, finfo.Size())
}

// SetCompression configures the zlib compression level for new objects added to the PDF.
// Supported levels are zlib.NoCompression, zlib.BestSpeed, zlib.BestCompression, or zlib.DefaultCompression.
func (d *Document) SetCompression(level int) {
	d.compressLevel = level
}

// SetUnit sets the default coordinate system scale for all subsequent operations
// on this document (e.g., signing appearances).
// By default, the unit is 1.0 (one PDF point = 1/72 inch).
func (d *Document) SetUnit(u float64) {
	d.unit = u
}

// Sign begins the process of adding a digital signature to the document.
// It returns a SignBuilder for fluent configuration of the signature properties.
// The signature is only finalized and written to the document when doc.Write() is called.
//
//   - signer: The private key used for signing.
//   - cert: The signer's public certificate.
//   - intermediates: Optional intermediate certificates to include in the certificate chain.
func (d *Document) Sign(signer crypto.Signer, cert *x509.Certificate, intermediates ...*x509.Certificate) *SignBuilder {
	sb := &SignBuilder{
		doc:    d,
		signer: signer,
		cert:   cert,
		digest: crypto.SHA256, // Default
		unit:   d.unit,        // Inherit from document
	}

	if len(intermediates) > 0 {
		chain := make([]*x509.Certificate, 0, len(intermediates)+1)
		chain = append(chain, cert)
		chain = append(chain, intermediates...)
		sb.chains = [][]*x509.Certificate{chain}
	}

	d.pendingSigns = append(d.pendingSigns, sb)
	return sb
}

// Timestamp adds a document-level timestamp signature.
func (d *Document) Timestamp(tsaURL string) *SignBuilder {
	return d.Sign(nil, nil).
		Type(DocumentTimestamp).
		tsaURL(tsaURL)
}

// Write executes all staged operations and writes the signed document.
// This method is implemented in execute.go using the fluent API state.

// Reader returns the low-level PDF reader, allowing direct access to the PDF Cross-Reference (XRef) table and objects.
func (d *Document) Reader() *pdflib.Reader {
	return d.rdr
}

// SetCompliance sets the PDF/A compliance level.
//
// WARNING: This method is currently a placeholder and does not enforce PDF/A compliance.
// It is preserved for future implementation.
func (d *Document) SetCompliance(c Compliance) {
	d.compliance = c
}
