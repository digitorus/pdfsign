package sign

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG format
)

func (context *SignContext) createAppearance(rect [4]float64) ([]byte, error) {
	if len(context.SignData.Appearance.Image) > 0 {
		return context.createImageAppearance(rect)
	}
	return context.createTextAppearance(rect)
}

// Helper functions for PDF resource components

// writeAppearanceHeader writes the header for the appearance stream.
//
// Should be closed by writeFormTypeAndLength.
func writeAppearanceHeader(buffer *bytes.Buffer, rectWidth, rectHeight float64) {
	buffer.WriteString("<<\n")
	buffer.WriteString("  /Type /XObject\n")
	buffer.WriteString("  /Subtype /Form\n")
	buffer.WriteString(fmt.Sprintf("  /BBox [0 0 %f %f]\n", rectWidth, rectHeight))
	buffer.WriteString("  /Matrix [1 0 0 1 0 0]\n") // No scaling or translation
}

func createFontResource(buffer *bytes.Buffer) {
	buffer.WriteString("   /Font <<\n")
	buffer.WriteString("     /F1 <<\n")
	buffer.WriteString("       /Type /Font\n")
	buffer.WriteString("       /Subtype /Type1\n")
	buffer.WriteString("       /BaseFont /Times-Roman\n")
	buffer.WriteString("     >>\n")
	buffer.WriteString("   >>\n")
}

func createImageResource(buffer *bytes.Buffer, imageObjectId uint32) {
	buffer.WriteString("   /XObject <<\n")
	buffer.WriteString(fmt.Sprintf("     /Im1 %d 0 R\n", imageObjectId))
	buffer.WriteString("   >>\n")
}

func writeFormTypeAndLength(buffer *bytes.Buffer, streamLength int) {
	buffer.WriteString("  /FormType 1\n")
	buffer.WriteString(fmt.Sprintf("  /Length %d\n", streamLength))
	buffer.WriteString(">>\n")
}

func writeBufferStream(buffer *bytes.Buffer, stream []byte) {
	buffer.WriteString("stream\n")
	buffer.Write(stream)
	buffer.WriteString("endstream\n")
}

func (context *SignContext) createImageXObject() ([]byte, error) {
	imageData := context.SignData.Appearance.Image

	// Read image configuration to get original dimensions
	img, _, err := image.DecodeConfig(bytes.NewReader(imageData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image configuration: %w", err)
	}

	// Use original image dimensions
	width := float64(img.Width)
	height := float64(img.Height)

	// Create basic PDF Image XObject
	var imageObject bytes.Buffer

	imageObject.WriteString("<<\n")
	imageObject.WriteString("  /Type /XObject\n")
	imageObject.WriteString("  /Subtype /Image\n")
	imageObject.WriteString(fmt.Sprintf("  /Width %.0f\n", width))
	imageObject.WriteString(fmt.Sprintf("  /Height %.0f\n", height))
	imageObject.WriteString("  /ColorSpace /DeviceRGB\n")
	imageObject.WriteString("  /BitsPerComponent 8\n")
	imageObject.WriteString("  /Filter /DCTDecode\n")
	imageObject.WriteString(fmt.Sprintf("  /Length %d\n", len(imageData)))
	imageObject.WriteString(">>\n")

	imageObject.WriteString("stream\n")
	imageObject.Write(imageData)
	imageObject.WriteString("\nendstream\n")

	return imageObject.Bytes(), nil
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
	buffer.WriteString("q\n")                                   // Save graphics state
	buffer.WriteString("BT\n")                                  // Begin text
	buffer.WriteString(fmt.Sprintf("/F1 %.2f Tf\n", fontSize))  // Set font and size
	buffer.WriteString(fmt.Sprintf("%.2f %.2f Td\n", x, y))     // Set text position
	buffer.WriteString("0.2 0.2 0.6 rg\n")                      // Set font color to ballpoint-like color (RGB)
	buffer.WriteString(fmt.Sprintf("%s Tj\n", pdfString(text))) // Show text
	buffer.WriteString("ET\n")                                  // End text
	buffer.WriteString("Q\n")                                   // Restore graphics state
}

func drawImage(buffer *bytes.Buffer, rectWidth, rectHeight float64) {
	// We save state twice on purpose due to the cm operation
	buffer.WriteString("q\n") // Save graphics state
	buffer.WriteString("q\n") // Save before image transformation
	buffer.WriteString(fmt.Sprintf("%.2f 0 0 %.2f 0 0 cm\n", rectWidth, rectHeight))
	buffer.WriteString("/Im1 Do\n") // Draw image
	buffer.WriteString("Q\n")       // Restore after transformation
	buffer.WriteString("Q\n")       // Restore graphics state
}

func (context *SignContext) createTextAppearance(rect [4]float64) ([]byte, error) {
	rectWidth := rect[2] - rect[0]
	rectHeight := rect[3] - rect[1]

	if rectWidth < 1 || rectHeight < 1 {
		return nil, fmt.Errorf("invalid rectangle dimensions: width %.2f and height %.2f must be greater than 0", rectWidth, rectHeight)
	}

	text := context.SignData.Signature.Info.Name

	fontSize, textX, textY := computeTextSizeAndPosition(text, rectWidth, rectHeight)

	var appearance_stream_buffer bytes.Buffer

	drawText(&appearance_stream_buffer, text, fontSize, textX, textY)

	// Create the appearance XObject
	var appearance_buffer bytes.Buffer
	writeAppearanceHeader(&appearance_buffer, rectWidth, rectHeight)

	// Resources dictionary with font
	appearance_buffer.WriteString("  /Resources <<\n")
	createFontResource(&appearance_buffer)
	appearance_buffer.WriteString("  >>\n")

	writeFormTypeAndLength(&appearance_buffer, appearance_stream_buffer.Len())

	writeBufferStream(&appearance_buffer, appearance_stream_buffer.Bytes())

	return appearance_buffer.Bytes(), nil
}

func (context *SignContext) createImageAppearance(rect [4]float64) ([]byte, error) {
	rectWidth := rect[2] - rect[0]
	rectHeight := rect[3] - rect[1]

	if rectWidth < 1 || rectHeight < 1 {
		return nil, fmt.Errorf("invalid rectangle dimensions: width %.2f and height %.2f must be greater than 0", rectWidth, rectHeight)
	}

	// Create and add the image XObject
	imageStream, err := context.createImageXObject()
	if err != nil {
		return nil, fmt.Errorf("failed to create image XObject: %w", err)
	}

	imageObjectId, err := context.addObject(imageStream)
	if err != nil {
		return nil, fmt.Errorf("failed to add image object: %w", err)
	}

	var appearance_stream_buffer bytes.Buffer

	drawImage(&appearance_stream_buffer, rectWidth, rectHeight)

	// Create the appearance XObject
	var appearance_buffer bytes.Buffer
	writeAppearanceHeader(&appearance_buffer, rectWidth, rectHeight)

	// Resources dictionary with XObject
	appearance_buffer.WriteString("  /Resources <<\n")
	createImageResource(&appearance_buffer, imageObjectId)
	appearance_buffer.WriteString("  >>\n")

	writeFormTypeAndLength(&appearance_buffer, appearance_stream_buffer.Len())

	writeBufferStream(&appearance_buffer, appearance_stream_buffer.Bytes())

	return appearance_buffer.Bytes(), nil
}
