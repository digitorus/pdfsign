package pdfsign

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/digitorus/pdfsign/fonts"
	"github.com/digitorus/pdfsign/internal/pdf"
)

// Fonts returns all registered fonts in the document.
func (d *Document) Fonts() []*Font {
	fonts := make([]*Font, 0, len(d.fonts))
	for _, f := range d.fonts {
		fonts = append(fonts, f)
	}
	return fonts
}

// Font returns a specific font by name, or nil if not found.
func (d *Document) Font(name string) *Font {
	// Check registered fonts first
	if f, ok := d.fonts[name]; ok {
		return f
	}
	// Check document fonts
	return nil
}

// AddFont registers a new font with the document.
// If a font with the same name already exists, the existing font is returned.
// If data is provided, it will be parsed for metrics (for accurate text measurement).
func (d *Document) AddFont(name string, data []byte) *Font {
	// Return existing font if already registered
	if existing, ok := d.fonts[name]; ok {
		return existing
	}

	// Compute hash for deduplication
	var hash string
	if len(data) > 0 {
		h := sha256.Sum256(data)
		hash = hex.EncodeToString(h[:])
	}

	font := &Font{
		Name:     name,
		Data:     data,
		Hash:     hash,
		Embedded: len(data) > 0,
	}

	// Parse metrics if we have font data
	if len(data) > 0 {
		metrics, err := fonts.ParseTTFMetrics(data)
		if err == nil {
			font.Metrics = metrics
		}
		// Silently ignore parse errors - font will use fallback widths
	}

	d.fonts[name] = font
	return font
}

// UseFont returns an existing font or adds a new one.
func (d *Document) UseFont(name string, data []byte) *Font {
	if f := d.Font(name); f != nil {
		return f
	}
	return d.AddFont(name, data)
}

// AddImage registers an image with the document.
// If an image with the same name already exists, the existing image is returned.
func (d *Document) AddImage(name string, data []byte) *Image {
	// Return existing image if already registered
	if existing, ok := d.images[name]; ok {
		return existing
	}

	// Compute hash for deduplication
	var hash string
	if len(data) > 0 {
		h := sha256.Sum256(data)
		hash = hex.EncodeToString(h[:])
	}

	img := &Image{
		Name: name,
		Data: data,
		Hash: hash,
	}
	d.images[name] = img
	return img
}

// Image returns a registered image by name.
func (d *Document) Image(name string) *Image {
	return d.images[name]
}

// Images returns all registered images in the document.
func (d *Document) Images() []*Image {
	images := make([]*Image, 0, len(d.images))
	for _, img := range d.images {
		images = append(images, img)
	}
	return images
}

// scanExistingFonts iterates through the PDF to find existing font resources.
func (d *Document) scanExistingFonts() error {
	fontsFound, err := pdf.ScanFonts(d.rdr)
	if err != nil {
		return err
	}

	for _, info := range fontsFound {
		if _, ok := d.fonts[info.Name]; !ok {
			d.fonts[info.Name] = &Font{
				Name:     info.Name,
				Embedded: true,
			}
		}
	}

	return nil
}
