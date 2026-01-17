package pdfsign

import (
	"github.com/digitorus/pdfsign/internal/render"
)

// Appearance represents the visual elements of a signature widget (text, images, shapes).
// All dimensions and coordinates within an Appearance are in PDF user space units (typically 1/72 inch).
type Appearance struct {
	width, height float64
	elements      []render.Element
	bgColor       *render.Color
	borderWidth   float64
	borderColor   *render.Color
}

// RenderInfo returns the internal representation of the appearance for rendering.
func (a *Appearance) RenderInfo() *render.AppearanceInfo {
	return &render.AppearanceInfo{
		Width:       a.width,
		Height:      a.height,
		Elements:    a.elements,
		BGColor:     a.bgColor,
		BorderWidth: a.borderWidth,
		BorderColor: a.borderColor,
	}
}

// Color is an alias for render.Color for backward compatibility.
// Deprecated: Use render.Color directly.
type Color = render.Color

// TextAlign is an alias for render.TextAlign for backward compatibility.
// Deprecated: Use render.TextAlign directly.
type TextAlign = render.TextAlign

// ImageScale is an alias for render.ImageScale for backward compatibility.
// Deprecated: Use render.ImageScale directly.
type ImageScale = render.ImageScale

const (
	// AlignLeft aligns text to the left.
	AlignLeft = render.AlignLeft
	// AlignCenter aligns text to the center.
	AlignCenter = render.AlignCenter
	// AlignRight aligns text to the right.
	AlignRight = render.AlignRight

	// ScaleStretch stretches the image to fill the rectangle.
	ScaleStretch = render.ScaleStretch
	// ScaleFit proportionally scales the image to fit within the rectangle.
	ScaleFit = render.ScaleFit
	// ScaleFill proportionally scales the image to fill the rectangle (may crop).
	ScaleFill = render.ScaleFill
)

// NewAppearance initializes a new signature appearance box with the given width and height.
// Dimensions are in PDF user space units (typically 1/72 inch).
// You can use the Millimeter or Centimeter constants for conversion (e.g., pdfsign.Millimeter * 50).
func NewAppearance(width, height float64) *Appearance {
	return &Appearance{
		width:  width,
		height: height,
	}
}

// Standard populates the appearance with a professional signature layout.
// It displays the signer's name prominently, followed by the reason, location, and signing date.
//
// Template variables ({{Name}}, {{Reason}}, {{Location}}, {{Date}}) are automatically
// expanded with the values from the SignBuilder.
//
// Example:
//
//	app := pdf.NewAppearance(300, 100).Standard()
func (a *Appearance) Standard() *Appearance {
	// Layout calculations
	lineHeight := a.height / 5 // 5 weighted rows
	padding := 4.0

	// Name (larger, bold-like via bigger size)
	a.Text("{{Name}}").
		Font(StandardFont(Helvetica), 14).
		Position(padding, a.height-lineHeight-padding)

	// Reason
	a.Text("Reason: {{Reason}}").
		Font(StandardFont(Helvetica), 10).
		Position(padding, a.height-2*lineHeight-padding)

	// Location
	a.Text("Location: {{Location}}").
		Font(StandardFont(Helvetica), 10).
		Position(padding, a.height-3*lineHeight-padding)

	// Date
	a.Text("Date: {{Date}}").
		Font(StandardFont(Helvetica), 10).
		Position(padding, a.height-4*lineHeight-padding)

	return a
}

// Background sets the fill color for the signature widget background.
func (a *Appearance) Background(r, g, b uint8) *Appearance {
	a.bgColor = &Color{r, g, b}
	return a
}

// Border draws a rectangular border around the signature widget with the specified width and RGB color.
func (a *Appearance) Border(width float64, r, g, b uint8) *Appearance {
	a.borderWidth = width
	a.borderColor = &Color{r, g, b}
	return a
}

// Image adds a raster image element (JPEG, PNG) to the appearance.
// Returns an ImageBuilder to configure position, size, and scaling.
func (a *Appearance) Image(img *Image) *ImageBuilder {
	return &ImageBuilder{
		appearance: a,
		image:      img,
		opacity:    1.0,
	}
}

// PDFObject adds a PDF page as a vector graphic element (Form XObject).
// This is useful for embedding vector graphics, logos, or other PDF content.
// The first page (page 1) is used by default.
func (a *Appearance) PDFObject(data []byte) *PDFObjectBuilder {
	return &PDFObjectBuilder{
		appearance: a,
		data:       data,
		page:       1,
	}
}

// PDFObjectBuilder builds a PDF Form XObject element from an embedded PDF.
type PDFObjectBuilder struct {
	appearance          *Appearance
	data                []byte
	page                int
	x, y, width, height float64
}

// Rect sets the position and size of the PDF object.
func (b *PDFObjectBuilder) Rect(x, y, width, height float64) *PDFObjectBuilder {
	b.x = x
	b.y = y
	b.width = width
	b.height = height
	b.finalize()
	return b
}

// Page sets which page of the PDF to use (1-indexed).
func (b *PDFObjectBuilder) Page(p int) *PDFObjectBuilder {
	b.page = p
	return b
}

func (b *PDFObjectBuilder) finalize() {
	if b.appearance != nil {
		b.appearance.elements = append(b.appearance.elements, render.PDFElement{
			Data:   b.data,
			Page:   b.page,
			X:      b.x,
			Y:      b.y,
			Width:  b.width,
			Height: b.height,
		})
	}
}

// Text adds a text string to the appearance and returns a TextBuilder for configuration.
// Supports template variables which are expanded at signing time.
func (a *Appearance) Text(content string) *TextBuilder {
	return &TextBuilder{
		appearance: a,
		content:    content,
		size:       10,
		color:      Color{0, 0, 0},
	}
}

// Width returns the appearance width.
func (a *Appearance) Width() float64 {
	return a.width
}

// Height returns the appearance height.
func (a *Appearance) Height() float64 {
	return a.height
}

// ImageBuilder builds an image element within an appearance.
type ImageBuilder struct {
	appearance *Appearance
	image      *Image
	x, y, w, h float64
	opacity    float64
	scale      ImageScale
}

// Rect sets the position and size of the image.
func (b *ImageBuilder) Rect(x, y, width, height float64) *ImageBuilder {
	b.x = x
	b.y = y
	b.w = width
	b.h = height
	return b
}

// Opacity sets the image opacity as a percentage from 0 (fully transparent) to 100 (fully opaque).
func (b *ImageBuilder) Opacity(percent float64) *ImageBuilder {
	b.opacity = percent / 100.0
	return b
}

// ScaleFit sets the scaling to fit within bounds.
func (b *ImageBuilder) ScaleFit() *ImageBuilder {
	b.scale = ScaleFit
	// Finalize and add to appearance
	b.finalize()
	return b
}

// ScaleStretch sets the scaling to stretch to fill bounds.
func (b *ImageBuilder) ScaleStretch() *ImageBuilder {
	b.scale = ScaleStretch
	b.finalize()
	return b
}

func (b *ImageBuilder) finalize() {
	if b.appearance != nil {
		b.appearance.elements = append(b.appearance.elements, render.ImageElement{
			Image:   b.image,
			X:       b.x,
			Y:       b.y,
			Width:   b.w,
			Height:  b.h,
			Opacity: b.opacity,
			Scale:   b.scale,
		})
	}
}

// TextBuilder builds a text element within an appearance.
type TextBuilder struct {
	appearance *Appearance
	content    string
	font       *Font
	size       float64
	x, y       float64
	color      Color
	align      TextAlign
	center     bool
	autoSize   bool
}

// Font sets the font for the text.
func (b *TextBuilder) Font(font *Font, size float64) *TextBuilder {
	b.font = font
	b.size = size
	return b
}

// Position sets the position of the text.
func (b *TextBuilder) Position(x, y float64) *TextBuilder {
	b.x = x
	b.y = y
	// Finalize and add to appearance
	b.finalize()
	return b
}

// SetColor sets the text color.
func (tb *TextBuilder) SetColor(r, g, b uint8) *TextBuilder {
	tb.color = Color{r, g, b}
	return tb
}

// Align sets the text alignment.
func (b *TextBuilder) Align(align TextAlign) *TextBuilder {
	b.align = align
	return b
}

// Center centers the text in the appearance.
func (b *TextBuilder) Center() *TextBuilder {
	b.center = true
	b.finalize()
	return b
}

// AutoScale enables automatic font resizing to fit the text within the appearance bounds.
func (b *TextBuilder) AutoScale() *TextBuilder {
	b.autoSize = true
	b.finalize()
	return b
}

func (b *TextBuilder) finalize() {
	if b.appearance != nil {
		b.appearance.elements = append(b.appearance.elements, render.TextElement{
			Content:  b.content,
			Font:     b.font,
			Size:     b.size,
			X:        b.x,
			Y:        b.y,
			Color:    b.color,
			Align:    b.align,
			Center:   b.center,
			AutoSize: b.autoSize,
		})
	}
}

// Line adds a line from (x1,y1) to (x2,y2).
func (a *Appearance) Line(x1, y1, x2, y2 float64) *LineBuilder {
	return &LineBuilder{
		appearance:  a,
		x1:          x1,
		y1:          y1,
		x2:          x2,
		y2:          y2,
		strokeColor: Color{0, 0, 0},
		strokeWidth: 1.0,
	}
}

// LineBuilder builds a line element.
type LineBuilder struct {
	appearance  *Appearance
	x1, y1      float64
	x2, y2      float64
	strokeColor Color
	strokeWidth float64
}

// Stroke sets the line color.
func (b *LineBuilder) Stroke(r, g, b_ uint8) *LineBuilder {
	b.strokeColor = Color{r, g, b_}
	b.finalize()
	return b
}

// Width sets the line width.
func (b *LineBuilder) Width(w float64) *LineBuilder {
	b.strokeWidth = w
	return b
}

func (b *LineBuilder) finalize() {
	if b.appearance != nil {
		b.appearance.elements = append(b.appearance.elements, render.LineElement{
			X1:          b.x1,
			Y1:          b.y1,
			X2:          b.x2,
			Y2:          b.y2,
			StrokeColor: b.strokeColor,
			StrokeWidth: b.strokeWidth,
		})
	}
}

// DrawRect adds a rectangle at (x, y) with given dimensions.
// Style with Fill(), Stroke(), StrokeWidth() - order doesn't matter.
func (a *Appearance) DrawRect(x, y, width, height float64) *ShapeBuilder {
	b := &ShapeBuilder{
		appearance:  a,
		shapeType:   "rect",
		x:           x,
		y:           y,
		width:       width,
		height:      height,
		strokeWidth: 1.0,
	}
	// Add to elements immediately - modifications update in place
	a.elements = append(a.elements, b)
	return b
}

// Circle adds a circle centered at (cx, cy) with radius r.
// Style with Fill(), Stroke(), StrokeWidth() - order doesn't matter.
func (a *Appearance) Circle(cx, cy, r float64) *ShapeBuilder {
	b := &ShapeBuilder{
		appearance:  a,
		shapeType:   "circle",
		cx:          cx,
		cy:          cy,
		r:           r,
		strokeWidth: 1.0,
	}
	// Add to elements immediately
	a.elements = append(a.elements, b)
	return b
}

// ShapeBuilder builds rect and circle elements.
type ShapeBuilder struct {
	appearance             *Appearance
	shapeType              string // "rect" or "circle"
	x, y, width, height    float64
	cx, cy, r              float64
	strokeColor, fillColor *Color
	strokeWidth            float64
}

func (*ShapeBuilder) IsElement() {}

// Stroke sets the stroke color.
func (b *ShapeBuilder) Stroke(r, g, b_ uint8) *ShapeBuilder {
	b.strokeColor = &Color{r, g, b_}
	return b
}

// Fill sets the fill color.
func (b *ShapeBuilder) Fill(r, g, b_ uint8) *ShapeBuilder {
	b.fillColor = &Color{r, g, b_}
	return b
}

// StrokeWidth sets the stroke width.
func (b *ShapeBuilder) StrokeWidth(w float64) *ShapeBuilder {
	b.strokeWidth = w
	return b
}
