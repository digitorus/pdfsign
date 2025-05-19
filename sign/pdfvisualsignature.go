package sign

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/digitorus/pdf"
)

// Define annotation flag constants.
const (
	AnnotationFlagInvisible      = 1 << 0
	AnnotationFlagHidden         = 1 << 1
	AnnotationFlagPrint          = 1 << 2
	AnnotationFlagNoZoom         = 1 << 3
	AnnotationFlagNoRotate       = 1 << 4
	AnnotationFlagNoView         = 1 << 5
	AnnotationFlagReadOnly       = 1 << 6
	AnnotationFlagLocked         = 1 << 7
	AnnotationFlagToggleNoView   = 1 << 8
	AnnotationFlagLockedContents = 1 << 9
)

// createVisualSignature creates a visual signature field in a PDF document.
// visible: determines if the signature field should be visible or not.
// pageNumber: the page number where the signature should be placed.
// rect: the rectangle defining the position and size of the signature field.
// Returns the visual signature string and an error if any.
func (context *SignContext) createVisualSignature(visible bool, pageNumber uint32, rect [4]float64) ([]byte, error) {
	var visual_signature bytes.Buffer

	visual_signature.WriteString("<<\n")

	// Define the object as an annotation.
	visual_signature.WriteString("  /Type /Annot\n")
	// Specify the annotation subtype as a widget.
	visual_signature.WriteString("  /Subtype /Widget\n")

	if visible {
		// Set the position and size of the signature field if visible.
		visual_signature.WriteString(fmt.Sprintf("  /Rect [%f %f %f %f]\n", rect[0], rect[1], rect[2], rect[3]))

		appearance, err := context.createAppearance(rect)
		if err != nil {
			return nil, fmt.Errorf("failed to create appearance: %w", err)
		}

		appearanceObjectId, err := context.addObject(appearance)
		if err != nil {
			return nil, fmt.Errorf("failed to add appearance object: %w", err)
		}

		// An appearance dictionary specifying how the annotation
		// shall be presented visually on the page (see 12.5.5, "Appearance streams").
		visual_signature.WriteString(fmt.Sprintf("  /AP << /N %d 0 R >>\n", appearanceObjectId))

	} else {
		// Set the rectangle to zero if the signature is invisible.
		visual_signature.WriteString("  /Rect [0 0 0 0]\n")
	}

	// Retrieve the root object from the PDF trailer.
	root := context.PDFReader.Trailer().Key("Root")
	// Get all keys from the root object.
	root_keys := root.Keys()
	found_pages := false
	for _, key := range root_keys {
		if key == "Pages" {
			// Check if the root object contains the "Pages" key.
			found_pages = true
			break
		}
	}

	// Get the pointer to the root object.
	rootPtr := root.GetPtr()
	// Store the root object reference in the catalog data.
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	if found_pages {
		// Find the page object by its number.
		page, err := findPageByNumber(root.Key("Pages"), pageNumber)
		if err != nil {
			return nil, err
		}

		// Get the pointer to the page object.
		page_ptr := page.GetPtr()

		// Store the page ID in the visual signature context so that we can add it to xref table later.
		context.VisualSignData.pageObjectId = page_ptr.GetID()

		// Add the page reference to the visual signature.
		visual_signature.WriteString("  /P " + strconv.Itoa(int(page_ptr.GetID())) + " " + strconv.Itoa(int(page_ptr.GetGen())) + " R\n")
	}

	// Define the annotation flags for the signature field (132)
	annotationFlags := AnnotationFlagPrint | AnnotationFlagLocked
	visual_signature.WriteString(fmt.Sprintf("  /F %d\n", annotationFlags))

	// Define the field type as a signature.
	visual_signature.WriteString("  /FT /Sig\n")
	// Set a unique title for the signature field.
	visual_signature.WriteString(fmt.Sprintf("  /T %s\n", pdfString("Signature "+strconv.Itoa(len(context.existingSignatures)+1))))

	// Reference the signature dictionary.
	visual_signature.WriteString(fmt.Sprintf("  /V %d 0 R\n", context.SignData.objectId))

	// Close the dictionary and end the object.
	visual_signature.WriteString(">>\n")

	return visual_signature.Bytes(), nil
}

func (context *SignContext) createIncPageUpdate(pageNumber, annot uint32) ([]byte, error) {
	var page_buffer bytes.Buffer

	// Retrieve the root object from the PDF trailer.
	root := context.PDFReader.Trailer().Key("Root")
	page, err := findPageByNumber(root.Key("Pages"), pageNumber)
	if err != nil {
		return nil, err
	}

	page_buffer.WriteString("<<\n")

	// TODO: Update digitorus/pdf to get raw values without resolving pointers
	for _, key := range page.Keys() {
		switch key {
		case "Parent":
			ptr := page.Key(key).GetPtr()
			page_buffer.WriteString(fmt.Sprintf("  /%s %d 0 R\n", key, ptr.GetID()))
		case "Contents":
			// Special handling for Contents - must preserve stream structure
			contentsValue := page.Key(key)
			if contentsValue.Kind() == pdf.Array {
				// If Contents is an array, keep it as an array reference
				page_buffer.WriteString("  /Contents [")
				for i := 0; i < contentsValue.Len(); i++ {
					ptr := contentsValue.Index(i).GetPtr()
					page_buffer.WriteString(fmt.Sprintf(" %d 0 R", ptr.GetID()))
				}
				page_buffer.WriteString(" ]\n")
			} else {
				// If Contents is a single reference, keep it as a single reference
				ptr := contentsValue.GetPtr()
				page_buffer.WriteString(fmt.Sprintf("  /%s %d 0 R\n", key, ptr.GetID()))
			}
		case "Annots":
			page_buffer.WriteString("  /Annots [\n")
			for i := 0; i < page.Key("Annots").Len(); i++ {
				ptr := page.Key(key).Index(i).GetPtr()
				page_buffer.WriteString(fmt.Sprintf("    %d 0 R\n", ptr.GetID()))
			}
			page_buffer.WriteString(fmt.Sprintf("    %d 0 R\n", annot))
			page_buffer.WriteString("  ]\n")
		default:
			page_buffer.WriteString(fmt.Sprintf("  /%s %s\n", key, page.Key(key).String()))
		}
	}

	if page.Key("Annots").IsNull() {
		page_buffer.WriteString(fmt.Sprintf("  /Annots [%d 0 R]\n", annot))
	}

	page_buffer.WriteString(">>\n")

	return page_buffer.Bytes(), nil
}

// Helper function to find a page by its number
func findPageByNumber(pages pdf.Value, pageNumber uint32) (pdf.Value, error) {
	page, remaining, err := findPageByNumberRec(pages, pageNumber)
	if err != nil {
		return pdf.Value{}, err
	}
	if remaining != 0 {
		return pdf.Value{}, fmt.Errorf("page number %d not found", pageNumber)
	}
	return page, nil
}

// Internal recursive helper that returns the found page and the remaining page number to find.
func findPageByNumberRec(pages pdf.Value, pageNumber uint32) (pdf.Value, uint32, error) {
	if pages.Key("Type").Name() == "Pages" {
		kids := pages.Key("Kids")
		for i := 0; i < kids.Len(); i++ {
			page, remaining, err := findPageByNumberRec(kids.Index(i), pageNumber)
			if err == nil && remaining == 0 {
				return page, 0, nil
			}
			pageNumber = remaining
		}
		return pdf.Value{}, pageNumber, fmt.Errorf("page number %d not found", pageNumber)
	} else if pages.Key("Type").Name() == "Page" {
		if pageNumber == 1 {
			return pages, 0, nil
		}
		return pdf.Value{}, pageNumber - 1, nil
	}
	return pdf.Value{}, pageNumber, fmt.Errorf("page number %d not found", pageNumber)
}
