package sign

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG format
)

func (context *SignContext) createAppearance(rect [4]float64) ([]byte, error) {
	if len(context.SignData.Signature.Info.Image) > 0 {
		return context.createImageAppearance(rect)
	}
	return context.createTextAppearance(rect)
}

func (context *SignContext) createTextAppearance(rect [4]float64) ([]byte, error) {
	rectWidth := rect[2] - rect[0]
	rectHeight := rect[3] - rect[1]

	if rectWidth < 1 || rectHeight < 1 {
		return nil, fmt.Errorf("invalid rectangle dimensions: width %.2f and height %.2f must be greater than 0", rectWidth, rectHeight)
	}

	var appearance_stream_buffer bytes.Buffer

	text := context.SignData.Signature.Info.Name

	// Calculate font size
	fontSize := rectHeight * 0.8                     // Use most of the height for the font
	textWidth := float64(len(text)) * fontSize * 0.5 // Approximate text width
	if textWidth > rectWidth {
		fontSize = rectWidth / (float64(len(text)) * 0.5) // Adjust font size to fit text within rect width
	}

	appearance_stream_buffer.WriteString("q\n")                                  // Save graphics state
	appearance_stream_buffer.WriteString("BT\n")                                 // Begin text
	appearance_stream_buffer.WriteString(fmt.Sprintf("/F1 %.2f Tf\n", fontSize)) // Font and size

	// Center text horizontally and vertically
	textWidth = float64(len(text)) * fontSize * 0.5
	textX := (rectWidth - textWidth) / 2
	if textX < 0 {
		textX = 0
	}
	textY := (rectHeight-fontSize)/2 + fontSize/3 // Approximate vertical centering

	appearance_stream_buffer.WriteString(fmt.Sprintf("%.2f %.2f Td\n", textX, textY)) // Position text
	appearance_stream_buffer.WriteString("0.2 0.2 0.6 rg\n")                          // Set font color to ballpoint-like color (RGB)
	appearance_stream_buffer.WriteString(fmt.Sprintf("%s Tj\n", pdfString(text)))     // Show text
	appearance_stream_buffer.WriteString("ET\n")                                      // End text
	appearance_stream_buffer.WriteString("Q\n")                                       // Restore graphics state

	// Create the appearance XObject
	var appearance_buffer bytes.Buffer
	appearance_buffer.WriteString("<<\n")
	appearance_buffer.WriteString("  /Type /XObject\n")
	appearance_buffer.WriteString("  /Subtype /Form\n")
	appearance_buffer.WriteString(fmt.Sprintf("  /BBox [0 0 %f %f]\n", rectWidth, rectHeight))
	appearance_buffer.WriteString("  /Matrix [1 0 0 1 0 0]\n") // No scaling or translation

	// Resources dictionary with font
	appearance_buffer.WriteString("  /Resources <<\n")
	appearance_buffer.WriteString("   /Font <<\n")
	appearance_buffer.WriteString("     /F1 <<\n")
	appearance_buffer.WriteString("       /Type /Font\n")
	appearance_buffer.WriteString("       /Subtype /Type1\n")
	appearance_buffer.WriteString("       /BaseFont /Times-Roman\n")
	appearance_buffer.WriteString("     >>\n")
	appearance_buffer.WriteString("   >>\n")
	appearance_buffer.WriteString("  >>\n")

	appearance_buffer.WriteString("  /FormType 1\n")
	appearance_buffer.WriteString(fmt.Sprintf("  /Length %d\n", appearance_stream_buffer.Len()))
	appearance_buffer.WriteString(">>\n")

	appearance_buffer.WriteString("stream\n")
	appearance_buffer.Write(appearance_stream_buffer.Bytes())
	appearance_buffer.WriteString("endstream\n")

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

	// We save state twice on purpose due to the cm operation
	appearance_stream_buffer.WriteString("q\n") // Save graphics state
	appearance_stream_buffer.WriteString("q\n") // Save before image transformation
	appearance_stream_buffer.WriteString(fmt.Sprintf("%.2f 0 0 %.2f 0 0 cm\n", rectWidth, rectHeight))
	appearance_stream_buffer.WriteString("/Im1 Do\n")
	appearance_stream_buffer.WriteString("Q\n") // Restore after transformation
	appearance_stream_buffer.WriteString("Q\n") // Restore graphics state

	// Create the appearance XObject
	var appearance_buffer bytes.Buffer
	appearance_buffer.WriteString("<<\n")
	appearance_buffer.WriteString("  /Type /XObject\n")

	appearance_buffer.WriteString("  /Subtype /Form\n")
	appearance_buffer.WriteString(fmt.Sprintf("  /BBox [0 0 %f %f]\n", rectWidth, rectHeight))

	// Resources dictionary with XObject
	appearance_buffer.WriteString("  /Resources <<\n")

	appearance_buffer.WriteString("   /XObject <<\n")
	appearance_buffer.WriteString(fmt.Sprintf("     /Im1 %d 0 R\n", imageObjectId))
	appearance_buffer.WriteString("   >>\n")
	appearance_buffer.WriteString("  >>\n")

	appearance_buffer.WriteString("  /FormType 1\n")
	appearance_buffer.WriteString(fmt.Sprintf("  /Length %d\n", appearance_stream_buffer.Len()))
	appearance_buffer.WriteString(">>\n")

	appearance_buffer.WriteString("stream\n")
	appearance_buffer.Write(appearance_stream_buffer.Bytes())
	appearance_buffer.WriteString("endstream\n")

	return appearance_buffer.Bytes(), nil
}

func (context *SignContext) createImageXObject() ([]byte, error) {
	imageData := context.SignData.Signature.Info.Image

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
	imageObject.WriteString("  /Filter /DCTDecode\n") // JPEG compression
	imageObject.WriteString(fmt.Sprintf("  /Length %d\n", len(imageData)))
	imageObject.WriteString(">>\n")

	imageObject.WriteString("stream\n")
	imageObject.Write(imageData)
	imageObject.WriteString("\nendstream\n")

	return imageObject.Bytes(), nil
}
