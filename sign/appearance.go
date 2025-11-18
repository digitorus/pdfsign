package sign

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG format
	_ "image/png"  // register PNG format
)

// Helper functions for PDF resource components

// writeAppearanceHeader writes the header for the appearance stream.
//
// Should be closed by writeFormTypeAndLength.
func writeAppearanceHeader(buffer *bytes.Buffer, rectWidth, rectHeight float64) {
	buffer.WriteString("<<\n")
	buffer.WriteString("  /Type /XObject\n")
	buffer.WriteString("  /Subtype /Form\n")
	fmt.Fprintf(buffer, "  /BBox [0 0 %f %f]\n", rectWidth, rectHeight)
	buffer.WriteString("  /Matrix [1 0 0 1 0 0]\n") // No scaling or translation
}

func createFontResource(buffer *bytes.Buffer) {
	buffer.WriteString("   /Font <<\n")
	buffer.WriteString("     /F1 <<\n")
	buffer.WriteString("       /Type /Font\n")
	buffer.WriteString("       /Subtype /Type1\n")
	buffer.WriteString("       /BaseFont /Times-Roman\n")
	buffer.WriteString("       /FirstChar 32\n") // Standard ASCII range start (space)
	buffer.WriteString("       /LastChar 255\n") // Standard ASCII range end
	buffer.WriteString("       /FontDescriptor <<\n")
	buffer.WriteString("         /Type /FontDescriptor\n")
	buffer.WriteString("         /FontName /Times-Roman\n")
	buffer.WriteString("         /Flags 32\n")
	buffer.WriteString("         /FontBBox [-168 -218 1000 898]\n")
	buffer.WriteString("         /ItalicAngle 0\n")
	buffer.WriteString("         /Ascent 683\n")
	buffer.WriteString("         /Descent -217\n")
	buffer.WriteString("         /CapHeight 662\n")
	buffer.WriteString("         /StemV 84\n") // StemH is optionnal per ISO 32000-1:2008
	buffer.WriteString("         /XHeight 450\n")
	buffer.WriteString("       >>\n")
	buffer.WriteString("     >>\n")
	buffer.WriteString("   >>\n")
}

func createImageResource(buffer *bytes.Buffer, imageObjectId uint32) {
	buffer.WriteString("   /XObject <<\n")
	fmt.Fprintf(buffer, "     /Im1 %d 0 R\n", imageObjectId)
	buffer.WriteString("   >>\n")
}

func writeFormTypeAndLength(buffer *bytes.Buffer, streamLength int) {
	buffer.WriteString("  /FormType 1\n")
	fmt.Fprintf(buffer, "  /Length %d\n", streamLength)
	buffer.WriteString(">>\n")
}

func writeAppearanceStreamBuffer(buffer *bytes.Buffer, stream []byte) {
	buffer.WriteString("stream\n")
	buffer.Write(stream)
	buffer.WriteString("\nendstream\n")
}

func (context *SignContext) createImageXObject() ([]byte, []byte, error) {
	imageData := context.SignData.Appearance.Image

	// Read image to get format and decode image data
	img, format, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Get image dimensions
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Create basic PDF Image XObject
	var imageObject bytes.Buffer
	var maskObjectBytes []byte

	imageObject.WriteString("<<\n")
	imageObject.WriteString("  /Type /XObject\n")
	imageObject.WriteString("  /Subtype /Image\n")
	imageObject.WriteString(fmt.Sprintf("  /Width %d\n", width))
	imageObject.WriteString(fmt.Sprintf("  /Height %d\n", height))
	imageObject.WriteString("  /ColorSpace /DeviceRGB\n")
	imageObject.WriteString("  /BitsPerComponent 8\n")

	var rgbData = new(bytes.Buffer)
	var alphaData = new(bytes.Buffer)

	// Handle different formats
	switch format {
	case "jpeg":
		imageObject.WriteString("  /Filter [/FlateDecode/DCTDecode]\n")
		rgbData = bytes.NewBuffer(imageData) // JPEG data is already in the correct format
	case "png":
		imageObject.WriteString("  /Filter /FlateDecode\n")

		// Extract RGB and alpha values from each pixel
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				// Get the color at pixel (x,y)
				originalColor := img.At(x, y)

				// Extract RGBA values (ranges from 0-65535 in Go's color model)
				r, g, b, a := originalColor.RGBA()

				// Convert to 8-bit (0-255)
				rgbData.WriteByte(byte(r >> 8))
				rgbData.WriteByte(byte(g >> 8))
				rgbData.WriteByte(byte(b >> 8))
				alphaData.WriteByte(byte(a >> 8))
			}
		}

		// If image has alpha channel, create soft mask
		if hasAlpha(img) {
			compressedAlphaData := compressData(alphaData.Bytes())

			// Create and add the soft mask object
			maskObjectBytes, err = context.createAlphaMask(width, height, compressedAlphaData)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create alpha mask: %w", err)
			}

			imageObject.WriteString(fmt.Sprintf("  /SMask %d 0 R\n", context.getNextObjectID()+1)) // the smask will be placed after the image
		}
	default:
		return nil, nil, fmt.Errorf("unsupported image format: %s", format)
	}

	compressedRgbData := compressData(rgbData.Bytes())

	imageObject.WriteString(fmt.Sprintf("  /Length %d\n", len(compressedRgbData)))
	imageObject.WriteString(">>\n")
	imageObject.WriteString("stream\n")
	imageObject.Write(compressedRgbData)
	imageObject.WriteString("\nendstream\n")

	return imageObject.Bytes(), maskObjectBytes, nil
}

func compressData(data []byte) []byte {
	var compressedData bytes.Buffer
	writer := zlib.NewWriter(&compressedData)
	// Write data and ensure the writer is closed before returning the buffer.
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil
	}

	if err := writer.Close(); err != nil {
		return nil
	}

	return compressedData.Bytes()
}

func (context *SignContext) createAlphaMask(width, height int, alphaData []byte) ([]byte, error) {
	var maskObject bytes.Buffer

	maskObject.WriteString("<<\n")
	maskObject.WriteString("  /Type /XObject\n")
	maskObject.WriteString("  /Subtype /Image\n")
	maskObject.WriteString(fmt.Sprintf("  /Width %d\n", width))
	maskObject.WriteString(fmt.Sprintf("  /Height %d\n", height))
	maskObject.WriteString("  /ColorSpace /DeviceGray\n")
	maskObject.WriteString("  /BitsPerComponent 8\n")
	maskObject.WriteString("  /Filter /FlateDecode\n")
	maskObject.WriteString(fmt.Sprintf("  /Length %d\n", len(alphaData)))
	maskObject.WriteString(">>\n")
	maskObject.WriteString("stream\n")
	maskObject.Write(alphaData)
	maskObject.WriteString("\nendstream\n")

	return maskObject.Bytes(), nil
}

// hasAlpha checks if the image has an alpha channel
func hasAlpha(img image.Image) bool {
	switch img.(type) {
	case *image.NRGBA, *image.RGBA:
		return true
	default:
		return false
	}
}

func computeTextSizeAndPosition(text string, rectWidth, rectHeight float64) (float64, float64, float64) {
	// Calculate font size
	fontSize := rectHeight * 0.8                     // Use most of the height for the font
	textWidth := float64(len(text)) * fontSize * 0.5 // Approximate text width
	if textWidth > rectWidth {
		fontSize = rectWidth / (float64(len(text)) * 0.5) // Adjust font size to fit text within rect width
	}

	// Center text horizontally and vertically
	textWidth = float64(len(text)) * fontSize * 0.5
	textX := (rectWidth - textWidth) / 2
	if textX < 0 {
		textX = 0
	}
	textY := (rectHeight-fontSize)/2 + fontSize/3 // Approximate vertical centering

	return fontSize, textX, textY
}

func drawText(buffer *bytes.Buffer, text string, fontSize float64, x, y float64) {
	buffer.WriteString("q\n")                       // Save graphics state
	buffer.WriteString("BT\n")                      // Begin text
	fmt.Fprintf(buffer, "/F1 %.2f Tf\n", fontSize)  // Set font and size
	fmt.Fprintf(buffer, "%.2f %.2f Td\n", x, y)     // Set text position
	buffer.WriteString("0.2 0.2 0.6 rg\n")          // Set font color to ballpoint-like color (RGB)
	fmt.Fprintf(buffer, "%s Tj\n", pdfString(text)) // Show text
	buffer.WriteString("ET\n")                      // End text
	buffer.WriteString("Q\n")                       // Restore graphics state
}

func drawImage(buffer *bytes.Buffer, rectWidth, rectHeight float64) {
	// We save state twice on purpose due to the cm operation
	buffer.WriteString("q\n") // Save graphics state
	buffer.WriteString("q\n") // Save before image transformation
	fmt.Fprintf(buffer, "%.2f 0 0 %.2f 0 0 cm\n", rectWidth, rectHeight)
	buffer.WriteString("/Im1 Do\n") // Draw image
	buffer.WriteString("Q\n")       // Restore after transformation
	buffer.WriteString("Q\n")       // Restore graphics state
}

func (context *SignContext) createAppearance(rect [4]float64) ([]byte, error) {
	rectWidth := rect[2] - rect[0]
	rectHeight := rect[3] - rect[1]

	if rectWidth < 1 || rectHeight < 1 {
		return nil, fmt.Errorf("invalid rectangle dimensions: width %.2f and height %.2f must be greater than 0", rectWidth, rectHeight)
	}

	hasImage := len(context.SignData.Appearance.Image) > 0
	shouldDisplayText := context.SignData.Appearance.ImageAsWatermark || !hasImage

	// Create the appearance XObject
	var appearance_buffer bytes.Buffer
	writeAppearanceHeader(&appearance_buffer, rectWidth, rectHeight)

	// Resources dictionary with font
	appearance_buffer.WriteString("  /Resources <<\n")

	if hasImage {
		// Create and add the image XObject
		imageBytes, maskObjectBytes, err := context.createImageXObject()
		if err != nil {
			return nil, fmt.Errorf("failed to create image XObject: %w", err)
		}

		imageObjectId, err := context.addObject(imageBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to add image object: %w", err)
		}

		if maskObjectBytes != nil {
			// Create and add the mask XObject
			_, err := context.addObject(maskObjectBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to add mask object: %w", err)
			}
		}

		createImageResource(&appearance_buffer, imageObjectId)
	}

	if shouldDisplayText {
		createFontResource(&appearance_buffer)
	}

	appearance_buffer.WriteString("  >>\n")

	// Create the appearance stream
	var appearance_stream_buffer bytes.Buffer

	if hasImage {
		drawImage(&appearance_stream_buffer, rectWidth, rectHeight)
	}

	if shouldDisplayText {
		text := context.SignData.Signature.Info.Name
		fontSize, textX, textY := computeTextSizeAndPosition(text, rectWidth, rectHeight)
		drawText(&appearance_stream_buffer, text, fontSize, textX, textY)
	}

	writeFormTypeAndLength(&appearance_buffer, appearance_stream_buffer.Len())

	writeAppearanceStreamBuffer(&appearance_buffer, appearance_stream_buffer.Bytes())

	return appearance_buffer.Bytes(), nil
}
