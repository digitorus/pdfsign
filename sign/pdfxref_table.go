package sign

import (
	"fmt"
)

// writeIncrXrefTable writes the incremental cross-reference table to the output buffer.
func (context *SignContext) writeIncrXrefTable() error {
	// Write xref header
	if _, err := context.OutputBuffer.Write([]byte("xref\n")); err != nil {
		return fmt.Errorf("failed to write incremental xref header: %w", err)
	}

	// Write updated entries
	for _, entry := range context.updatedXrefEntries {
		pageXrefObj := fmt.Sprintf("%d %d\n", entry.ID, 1)
		if _, err := context.OutputBuffer.Write([]byte(pageXrefObj)); err != nil {
			return fmt.Errorf("failed to write updated xref object: %w", err)
		}

		xrefLine := fmt.Sprintf("%010d 00000 n\r\n", entry.Offset)
		if _, err := context.OutputBuffer.Write([]byte(xrefLine)); err != nil {
			return fmt.Errorf("failed to write updated incremental xref entry: %w", err)
		}
	}

	// Write xref subsection header
	startXrefObj := fmt.Sprintf("%d %d\n", context.lastXrefID+1, len(context.newXrefEntries))
	if _, err := context.OutputBuffer.Write([]byte(startXrefObj)); err != nil {
		return fmt.Errorf("failed to write starting xref object: %w", err)
	}

	// Write new entries
	for _, entry := range context.newXrefEntries {
		xrefLine := fmt.Sprintf("%010d 00000 n\r\n", entry.Offset)
		if _, err := context.OutputBuffer.Write([]byte(xrefLine)); err != nil {
			return fmt.Errorf("failed to write incremental xref entry: %w", err)
		}
	}

	return nil
}
