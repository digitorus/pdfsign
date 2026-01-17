package forms_test

import (
	"fmt"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// ExampleDocument_FormFields demonstrates how to list form fields in a PDF.
func ExampleDocument_FormFields() {
	// Open a PDF with form fields
	doc, err := pdfsign.OpenFile(testpki.GetTestFile("testfiles/testfile_form.pdf"))
	if err != nil {
		fmt.Println(err)
		return
	}

	// List fields
	fields := doc.FormFields()

	// Print the first few fields for demonstration
	for i, f := range fields {
		if i >= 3 {
			break
		}
		fmt.Printf("Field: %s (Type: %s)\n", f.Name, f.Type)
	}

	// Output:
	// Field: Given Name Text Box (Type: Tx)
	// Field: Family Name Text Box (Type: Tx)
	// Field: Address 1 Text Box (Type: Tx)
}
