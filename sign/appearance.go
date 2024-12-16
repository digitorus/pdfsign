package sign

import (
	"bytes"
	"fmt"
)

func (context *SignContext) createAppearance(rect [4]float64) ([]byte, error) {
	text := context.SignData.Signature.Info.Name

	rectWidth := rect[2] - rect[0]
	rectHeight := rect[3] - rect[1]

	if rectWidth < 1 || rectHeight < 1 {
		return nil, fmt.Errorf("invalid rectangle dimensions: width %.2f and height %.2f must be greater than 0", rectWidth, rectHeight)
	}

	// Calculate font size
	fontSize := rectHeight * 0.8                     // Initial font size
	textWidth := float64(len(text)) * fontSize * 0.5 // Approximate text width
	if textWidth > rectWidth {
		fontSize = rectWidth / (float64(len(text)) * 0.5) // Adjust font size to fit text within rect width
	}

	var appearance_stream_buffer bytes.Buffer
	appearance_stream_buffer.WriteString("q\n")                                           // Save graphics state
	appearance_stream_buffer.WriteString("BT\n")                                          // Begin text
	appearance_stream_buffer.WriteString(fmt.Sprintf("/F1 %.2f Tf\n", fontSize))          // Font and size
	appearance_stream_buffer.WriteString(fmt.Sprintf("0 %.2f Td\n", rectHeight-fontSize)) // Position in unit square
	appearance_stream_buffer.WriteString("0.2 0.2 0.6 rg\n")                              // Set font color to ballpoint-like color (RGB)
	appearance_stream_buffer.WriteString(fmt.Sprintf("%s Tj\n", pdfString(text)))         // Show text
	appearance_stream_buffer.WriteString("ET\n")                                          // End text
	appearance_stream_buffer.WriteString("Q\n")                                           // Restore graphics state

	var appearance_buffer bytes.Buffer
	appearance_buffer.WriteString("<<\n")
	appearance_buffer.WriteString("  /Type /XObject\n")
	appearance_buffer.WriteString("  /Subtype /Form\n")
	appearance_buffer.WriteString(fmt.Sprintf("  /BBox [0 0 %f %f]\n", rectWidth, rectHeight))
	appearance_buffer.WriteString("  /Matrix [1 0 0 1 0 0]\n") // No scaling or translation

	// Resources dictionary
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
