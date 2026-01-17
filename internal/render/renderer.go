package render

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"time"

	"github.com/digitorus/pdfsign/fonts"
	"github.com/digitorus/pdfsign/internal/pdf"
	"github.com/digitorus/pdfsign/sign"
)

// NewAppearanceRenderer returns a function that renders an appearance to PDF operators.
func NewAppearanceRenderer(a *AppearanceInfo, signerName, reason, location string) func(context *sign.SignContext, rect [4]float64) ([]byte, error) {
	return func(context *sign.SignContext, rect [4]float64) ([]byte, error) {
		rectWidth := rect[2] - rect[0]
		rectHeight := rect[3] - rect[1]

		var buf bytes.Buffer
		buf.WriteString("<<\n")
		buf.WriteString("  /Type /XObject\n")
		buf.WriteString("  /Subtype /Form\n")
		fmt.Fprintf(&buf, "  /BBox [0 0 %f %f]\n", rectWidth, rectHeight)
		buf.WriteString("  /Matrix [1 0 0 1 0 0]\n")
		buf.WriteString("  /Resources <<\n")

		var xobjects bytes.Buffer
		var fontsBuf bytes.Buffer
		hasXObjects := false
		hasFonts := false

		var stream bytes.Buffer

		if a.BGColor != nil {
			fmt.Fprintf(&stream, "q %.2f %.2f %.2f rg 0 0 %.2f %.2f re f Q\n",
				float64(a.BGColor.R)/255.0, float64(a.BGColor.G)/255.0, float64(a.BGColor.B)/255.0,
				rectWidth, rectHeight)
		}

		if a.BorderWidth > 0 && a.BorderColor != nil {
			fmt.Fprintf(&stream, "q %.2f %.2f %.2f RG %.2f w 0 0 %.2f %.2f re S Q\n",
				float64(a.BorderColor.R)/255.0, float64(a.BorderColor.G)/255.0, float64(a.BorderColor.B)/255.0,
				a.BorderWidth, rectWidth, rectHeight)
		}

		tplCtx := TemplateContext{
			Name:     signerName,
			Reason:   reason,
			Location: location,
			Date:     time.Now(),
		}

		imgCount := 0
		fontCount := 0
		fontMap := make(map[*fonts.Font]string)

		for _, el := range a.Elements {
			switch e := el.(type) {
			case ImageElement:
				imgCount++
				imgName := fmt.Sprintf("Im%d", imgCount)

				imgObjID, err := RegisterImage(context, e.Image.Data)
				if err != nil {
					return nil, err
				}

				if !hasXObjects {
					xobjects.WriteString("    /XObject <<\n")
					hasXObjects = true
				}
				fmt.Fprintf(&xobjects, "      /%s %d 0 R\n", imgName, imgObjID)

				fmt.Fprintf(&stream, "q\n")
				fmt.Fprintf(&stream, "  %f 0 0 %f %f %f cm\n", e.Width, e.Height, e.X, e.Y)
				fmt.Fprintf(&stream, "  /%s Do\n", imgName)
				fmt.Fprintf(&stream, "Q\n")

			case TextElement:
				content := ExpandTemplateVariables(e.Content, tplCtx)
				font := e.Font
				if font == nil {
					font = fonts.Standard(fonts.Helvetica)
				}

				fontName, ok := fontMap[font]
				if !ok {
					fontCount++
					fontName = fmt.Sprintf("F%d", fontCount)
					fontMap[font] = fontName

					if !hasFonts {
						fontsBuf.WriteString("    /Font <<\n")
						hasFonts = true
					}
					fontObjID, err := RegisterFont(context, font)
					if err != nil {
						return nil, err
					}
					fmt.Fprintf(&fontsBuf, "      /%s %d 0 R\n", fontName, fontObjID)
				}

				stream.WriteString("q\nBT\n")
				fmt.Fprintf(&stream, "  /%s %.2f Tf\n", fontName, e.Size)
				fmt.Fprintf(&stream, "  %.2f %.2f %.2f rg\n", float64(e.Color.R)/255.0, float64(e.Color.G)/255.0, float64(e.Color.B)/255.0)

				if e.AutoSize {
					minSize := 4.0
					for e.Size > minSize {
						var textWidth float64
						if font != nil && font.Metrics != nil {
							textWidth = font.Metrics.GetStringWidth(content, e.Size)
						} else {
							textWidth = float64(len(content)) * e.Size * 0.5
						}
						if textWidth < rectWidth-4 && e.Size < rectHeight-4 {
							break
						}
						e.Size -= 1.0
					}
				}

				x, y := e.X, e.Y
				if e.Center {
					var textWidth float64
					if font != nil && font.Metrics != nil {
						textWidth = font.Metrics.GetStringWidth(content, e.Size)
					} else {
						textWidth = float64(len(content)) * e.Size * 0.5
					}
					x = (rectWidth - textWidth) / 2
					y = (rectHeight - e.Size) / 2
					if x < 0 {
						x = 0
					}
					if y < 0 {
						y = 0
					}
				}

				fmt.Fprintf(&stream, "  %.2f %.2f Td\n", x, y)
				fmt.Fprintf(&stream, "  <%s> Tj\n", hex.EncodeToString([]byte(content)))
				stream.WriteString("ET\nQ\n")

			case LineElement:
				stream.WriteString("q\n")
				fmt.Fprintf(&stream, "%.2f w\n", e.StrokeWidth)
				fmt.Fprintf(&stream, "%.2f %.2f %.2f RG\n", float64(e.StrokeColor.R)/255.0, float64(e.StrokeColor.G)/255.0, float64(e.StrokeColor.B)/255.0)
				fmt.Fprintf(&stream, "%.2f %.2f m\n", e.X1, e.Y1)
				fmt.Fprintf(&stream, "%.2f %.2f l\n", e.X2, e.Y2)
				stream.WriteString("S\nQ\n")

			case ShapeElement:
				stream.WriteString("q\n")
				fmt.Fprintf(&stream, "%.2f w\n", e.StrokeWidth)
				if e.FillColor != nil {
					fmt.Fprintf(&stream, "%.2f %.2f %.2f rg\n", float64(e.FillColor.R)/255.0, float64(e.FillColor.G)/255.0, float64(e.FillColor.B)/255.0)
				}
				if e.StrokeColor != nil {
					fmt.Fprintf(&stream, "%.2f %.2f %.2f RG\n", float64(e.StrokeColor.R)/255.0, float64(e.StrokeColor.G)/255.0, float64(e.StrokeColor.B)/255.0)
				}

				switch e.ShapeType {
				case "rect":
					fmt.Fprintf(&stream, "%.2f %.2f %.2f %.2f re\n", e.X, e.Y, e.Width, e.Height)
				case "circle":
					k := 0.5522847498 * e.R
					fmt.Fprintf(&stream, "%.2f %.2f m\n", e.CX+e.R, e.CY)
					fmt.Fprintf(&stream, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", e.CX+e.R, e.CY+k, e.CX+k, e.CY+e.R, e.CX, e.CY+e.R)
					fmt.Fprintf(&stream, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", e.CX-k, e.CY+e.R, e.CX-e.R, e.CY+k, e.CX-e.R, e.CY)
					fmt.Fprintf(&stream, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", e.CX-e.R, e.CY-k, e.CX-k, e.CY-e.R, e.CX, e.CY-e.R)
					fmt.Fprintf(&stream, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", e.CX+k, e.CY-e.R, e.CX+e.R, e.CY-k, e.CX+e.R, e.CY)
				}

				if e.FillColor != nil && e.StrokeColor != nil {
					stream.WriteString("B\n")
				} else if e.FillColor != nil {
					stream.WriteString("f\n")
				} else if e.StrokeColor != nil {
					stream.WriteString("S\n")
				}
				stream.WriteString("Q\n")

			case PDFElement:
				contentStream, bbox, err := pdf.ExtractPageAsXObject(e.Data, e.Page)
				if err != nil {
					continue
				}
				if len(contentStream) == 0 {
					continue
				}

				imgCount++
				xobjName := fmt.Sprintf("Pdf%d", imgCount)

				srcWidth := bbox[2] - bbox[0]
				srcHeight := bbox[3] - bbox[1]
				scaleX := e.Width / srcWidth
				scaleY := e.Height / srcHeight

				xobjDict := fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [%.2f %.2f %.2f %.2f] /Length %d >>\nstream\n",
					bbox[0], bbox[1], bbox[2], bbox[3], len(contentStream))
				xobjData := append([]byte(xobjDict), contentStream...)
				xobjData = append(xobjData, []byte("\nendstream")...)

				xobjID, err := context.AddObject(xobjData)
				if err != nil {
					continue
				}

				if !hasXObjects {
					xobjects.WriteString("    /XObject <<\n")
					hasXObjects = true
				}
				fmt.Fprintf(&xobjects, "      /%s %d 0 R\n", xobjName, xobjID)

				stream.WriteString("q\n")
				fmt.Fprintf(&stream, "%.4f 0 0 %.4f %.2f %.2f cm\n", scaleX, scaleY, e.X, e.Y)
				fmt.Fprintf(&stream, "/%s Do\n", xobjName)
				stream.WriteString("Q\n")
			}
		}

		if hasXObjects {
			xobjects.WriteString("    >>\n")
			buf.Write(xobjects.Bytes())
		}
		if hasFonts {
			fontsBuf.WriteString("    >>\n")
			buf.Write(fontsBuf.Bytes())
		}

		buf.WriteString("  >>\n")
		buf.WriteString("  /FormType 1\n")
		fmt.Fprintf(&buf, "  /Length %d\n", stream.Len())
		buf.WriteString(">>\nstream\n")
		buf.Write(stream.Bytes())
		buf.WriteString("\nendstream\n")

		return buf.Bytes(), nil
	}
}

// RegisterImage encodes and registers an image object in the PDF.
func RegisterImage(context *sign.SignContext, data []byte) (uint32, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("invalid image data")
	}

	srcImg, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("failed to decode image: %v", err)
	}

	bounds := srcImg.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	var rgbBuf, alphaBuf bytes.Buffer
	compressLevel := zlib.DefaultCompression
	if context != nil {
		compressLevel = context.CompressLevel
	}

	var rgbWriter, alphaWriter io.Writer = &rgbBuf, &alphaBuf
	var zlibRgb, zlibAlpha *zlib.Writer
	useCompression := compressLevel != zlib.NoCompression

	if useCompression {
		zlibRgb, _ = zlib.NewWriterLevel(&rgbBuf, compressLevel)
		zlibAlpha, _ = zlib.NewWriterLevel(&alphaBuf, compressLevel)
		rgbWriter, alphaWriter = zlibRgb, zlibAlpha
	}

	hasAlpha := false
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := srcImg.At(x, y)
			r, g, b, a := c.RGBA()
			a8 := uint8(a >> 8)
			if a8 < 255 {
				hasAlpha = true
			}
			alphaWriter.Write([]byte{a8})
			rgbWriter.Write([]byte{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8)})
		}
	}

	if useCompression {
		zlibRgb.Close()
		zlibAlpha.Close()
	}

	var smaskID uint32
	if hasAlpha {
		smaskDict := fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 %s /Length %d >>\nstream\n",
			width, height, ifElse(useCompression, "/Filter /FlateDecode", ""), alphaBuf.Len())
		smaskData := append([]byte(smaskDict), alphaBuf.Bytes()...)
		smaskData = append(smaskData, []byte("\nendstream")...)
		smaskID, _ = context.AddObject(smaskData)
	}

	var objBuf bytes.Buffer
	objBuf.WriteString("<< /Type /XObject /Subtype /Image\n")
	fmt.Fprintf(&objBuf, "  /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8\n", width, height)
	if smaskID != 0 {
		fmt.Fprintf(&objBuf, "  /SMask %d 0 R\n", smaskID)
	}

	if format == "jpeg" && !hasAlpha {
		fmt.Fprintf(&objBuf, "  /Filter /DCTDecode /Length %d >>\nstream\n", len(data))
		objBuf.Write(data)
	} else {
		fmt.Fprintf(&objBuf, "  %s /Length %d >>\nstream\n", ifElse(useCompression, "/Filter /FlateDecode", ""), rgbBuf.Len())
		objBuf.Write(rgbBuf.Bytes())
	}
	objBuf.WriteString("\nendstream")

	return context.AddObject(objBuf.Bytes())
}

// RegisterFont registers a font in the PDF.
func RegisterFont(context *sign.SignContext, f *fonts.Font) (uint32, error) {
	if f != nil && len(f.Data) > 0 {
		compressLevel := zlib.DefaultCompression
		if context != nil {
			compressLevel = context.CompressLevel
		}

		fontData := f.Data
		filter := ""
		if compressLevel != zlib.NoCompression {
			var buf bytes.Buffer
			zw, _ := zlib.NewWriterLevel(&buf, compressLevel)
			zw.Write(f.Data)
			zw.Close()
			fontData = buf.Bytes()
			filter = "/Filter /FlateDecode"
		}

		streamDict := fmt.Sprintf("<< /Length %d /Length1 %d %s >>\nstream\n", len(fontData), len(f.Data), filter)
		streamData := append([]byte(streamDict), fontData...)
		streamData = append(streamData, []byte("\nendstream")...)
		fontStreamID, _ := context.AddObject(streamData)

		fdDict := fmt.Sprintf("<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [-500 -200 1000 900] /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 /FontFile2 %d 0 R >>", f.Name, fontStreamID)
		descriptorID, _ := context.AddObject([]byte(fdDict))

		var fontBuf bytes.Buffer
		fmt.Fprintf(&fontBuf, "<< /Type /Font /Subtype /TrueType /BaseFont /%s /FontDescriptor %d 0 R /FirstChar 32 /LastChar 255 /Encoding /WinAnsiEncoding /Widths [", f.Name, descriptorID)
		if f.Metrics != nil {
			for _, w := range f.Metrics.GetWidthsArray() {
				fmt.Fprintf(&fontBuf, " %d", w)
			}
		} else {
			for i := 32; i <= 255; i++ {
				fontBuf.WriteString(" 500")
			}
		}
		fontBuf.WriteString(" ] >>")
		return context.AddObject(fontBuf.Bytes())
	}

	baseFont := "Helvetica"
	if f != nil && f.Name != "" {
		baseFont = f.Name
	}
	fontDict := fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", baseFont)
	return context.AddObject([]byte(fontDict))
}

func ifElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
