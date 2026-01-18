// Package images provides image resources for PDF documents.
//
// This package contains types for working with raster images (JPEG, PNG)
// that can be used in PDF signature appearances.
package images

// Image represents an image resource that can be used in PDF appearances.
type Image struct {
	Name string // Identifier for the image
	Data []byte // Raw image data (JPEG or PNG)
	Hash string // SHA256 hash of image data for deduplication
}
