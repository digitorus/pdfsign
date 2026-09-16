package render

import (
	"github.com/digitorus/pdfsign/fonts"
	"github.com/digitorus/pdfsign/images"
)

// Color represents an RGB color.
type Color struct {
	R, G, B uint8
}

// TextAlign defines horizontal text alignment.
type TextAlign int

const (
	// AlignLeft aligns text to the left.
	AlignLeft TextAlign = iota
	// AlignCenter aligns text to the center.
	AlignCenter
	// AlignRight aligns text to the right.
	AlignRight
)

// ImageScale defines how images are scaled.
type ImageScale int

const (
	// ScaleStretch stretches the image to fill the rectangle.
	ScaleStretch ImageScale = iota
	// ScaleFit proportionally scales the image to fit within the rectangle.
	ScaleFit
	// ScaleFill proportionally scales the image to fill the rectangle (may crop).
	ScaleFill
)

// AppearanceInfo contains the data needed to render a signature appearance.
type AppearanceInfo struct {
	Width, Height float64
	Elements      []Element
	BGColor       *Color
	BorderWidth   float64
	BorderColor   *Color
}

// Element is an interface for visual elements in an appearance.
type Element interface {
	IsElement()
}

// ImageElement defines a raster image in an appearance.
type ImageElement struct {
	Image               *images.Image
	X, Y, Width, Height float64
	Opacity             float64
	Scale               ImageScale
}

func (ImageElement) IsElement() {}

// TextElement defines a text string in an appearance.
type TextElement struct {
	Content  string
	Font     *fonts.Font
	Size     float64
	X, Y     float64
	Color    Color
	Align    TextAlign
	Center   bool
	AutoSize bool
}

func (TextElement) IsElement() {}

// ShapeElement defines a geometric shape (rect or circle).
type ShapeElement struct {
	ShapeType              string // "rect" or "circle"
	X, Y, Width, Height    float64
	CX, CY, R              float64
	StrokeColor, FillColor *Color
	StrokeWidth            float64
}

func (ShapeElement) IsElement() {}

// LineElement defines a line shape in an appearance.
type LineElement struct {
	X1, Y1, X2, Y2 float64
	StrokeColor    Color
	StrokeWidth    float64
}

func (LineElement) IsElement() {}

// PDFElement defines an embedded PDF page in an appearance.
type PDFElement struct {
	Data                []byte
	Page                int
	X, Y, Width, Height float64
}

func (PDFElement) IsElement() {}
