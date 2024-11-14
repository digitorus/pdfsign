package sign

import (
	"fmt"
	"strconv"

	"github.com/digitorus/pdf"
)

// Define annotation flag constants
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
func (context *SignContext) createVisualSignature(visible bool, pageNumber int, rect [4]float64) (visual_signature string, err error) {
	// Initialize the visual signature object with its ID.
	visual_signature = strconv.Itoa(int(context.VisualSignData.ObjectId)) + " 0 obj\n"
	// Define the object as an annotation.
	visual_signature += "<< /Type /Annot"
	// Specify the annotation subtype as a widget.
	visual_signature += " /Subtype /Widget"

	if visible {
		// Set the position and size of the signature field if visible.
		visual_signature += fmt.Sprintf(" /Rect [%f %f %f %f]", rect[0], rect[1], rect[2], rect[3])
	} else {
		// Set the rectangle to zero if the signature is invisible.
		visual_signature += " /Rect [0 0 0 0]"
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
			return "", err
		}

		// Get the pointer to the page object.
		page_ptr := page.GetPtr()

		// Store the page ID in the visual signature context so that we can add it to xref table later.
		context.VisualSignData.PageId = page_ptr.GetID()

		// Add the page reference to the visual signature.
		visual_signature += " /P " + strconv.Itoa(int(page_ptr.GetID())) + " " + strconv.Itoa(int(page_ptr.GetGen())) + " R"
	}

	// Define the annotation flags for the signature field (132)
	//annotationFlags := AnnotationFlagPrint | AnnotationFlagNoZoom | AnnotationFlagNoRotate | AnnotationFlagReadOnly | AnnotationFlagLockedContents
	visual_signature += fmt.Sprintf(" /F %d", 132)
	// Define the field type as a signature.
	visual_signature += " /FT /Sig"
	// Set a unique title for the signature field.
	visual_signature += " /T " + pdfString("Signature "+strconv.Itoa(len(context.SignData.ExistingSignatures)+1))

	// (Optional) A set of bit flags specifying the interpretation of specific entries
	// in this dictionary. A value of 1 for the flag indicates that the associated entry
	// is a required constraint. A value of 0 indicates that the associated entry is
	// an optional constraint. Bit positions are 1 (Filter); 2 (SubFilter); 3 (V); 4
	// (Reasons); 5 (LegalAttestation); 6 (AddRevInfo); and 7 (DigestMethod).
	// For PDF 2.0 the following bit flags are added: 8 (Lockdocument); and 9
	// (AppearanceFilter). Default value: 0.
	visual_signature += " /Ff 0"

	// Reference the signature dictionary.
	visual_signature += " /V " + strconv.Itoa(int(context.SignData.ObjectId)) + " 0 R"

	// Close the dictionary and end the object.
	visual_signature += " >>"
	visual_signature += "\nendobj\n"

	return visual_signature, nil
}

// Helper function to find a page by its number
func findPageByNumber(pages pdf.Value, pageNumber int) (pdf.Value, error) {
	if pages.Key("Type").Name() == "Pages" {
		kids := pages.Key("Kids")
		for i := 0; i < kids.Len(); i++ {
			page, err := findPageByNumber(kids.Index(i), pageNumber)
			if err == nil {
				return page, nil
			}
		}
	} else if pages.Key("Type").Name() == "Page" {
		if pageNumber == 1 {
			return pages, nil
		}
		pageNumber--
	}
	return pdf.Value{}, fmt.Errorf("page number %d not found", pageNumber)
}
