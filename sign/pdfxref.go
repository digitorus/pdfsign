package sign

import (
	"bytes"
	"fmt"
)

type xrefEntry struct {
	ID         uint32
	Offset     int64
	Generation int
	Free       bool
}

const (
	objectFooter = "\nendobj\n"
)

func (context *SignContext) getNextObjectID() uint32 {
	if context.lastXrefID == 0 {
		lastXrefID, err := context.getLastObjectIDFromXref()
		if err != nil {
			return 0
		}
		context.lastXrefID = lastXrefID
	}

	objectID := context.lastXrefID + uint32(len(context.newXrefEntries)) + 1
	return objectID
}

func (context *SignContext) addObject(object []byte) (uint32, error) {
	if context.lastXrefID == 0 {
		lastXrefID, err := context.getLastObjectIDFromXref()
		if err != nil {
			return 0, fmt.Errorf("failed to get last object ID: %w", err)
		}
		context.lastXrefID = lastXrefID
	}

	objectID := context.lastXrefID + uint32(len(context.newXrefEntries)) + 1
	context.newXrefEntries = append(context.newXrefEntries, xrefEntry{
		ID:     objectID,
		Offset: int64(context.OutputBuffer.Buff.Len()) + 1,
	})

	err := context.writeObject(objectID, object)
	if err != nil {
		return 0, fmt.Errorf("failed to write object: %w", err)
	}

	return objectID, nil
}

func (context *SignContext) updateObject(id uint32, object []byte) error {
	context.updatedXrefEntries = append(context.updatedXrefEntries, xrefEntry{
		ID:     id,
		Offset: int64(context.OutputBuffer.Buff.Len()) + 1,
	})

	err := context.writeObject(id, object)
	if err != nil {
		return fmt.Errorf("failed to write object: %w", err)
	}

	return nil
}

func (context *SignContext) writeObject(id uint32, object []byte) error {
	// Write the object header
	if _, err := fmt.Fprintf(context.OutputBuffer, "\n%d 0 obj\n", id); err != nil {
		return fmt.Errorf("failed to write object header: %w", err)
	}

	// Write the object content
	object = bytes.TrimSpace(object)
	if _, err := context.OutputBuffer.Write(object); err != nil {
		return fmt.Errorf("failed to write object content: %w", err)
	}

	// Write the object footer
	if _, err := context.OutputBuffer.Write([]byte(objectFooter)); err != nil {
		return fmt.Errorf("failed to write object footer: %w", err)
	}

	return nil
}

// writeXref writes the cross-reference table or stream based on the PDF type.
func (context *SignContext) writeXref() error {
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline before xref: %w", err)
	}
	context.NewXrefStart = int64(context.OutputBuffer.Buff.Len())

	switch context.PDFReader.XrefInformation.Type {
	case "table":
		return context.writeIncrXrefTable()
	case "stream":
		return context.writeXrefStream()
	default:
		return fmt.Errorf("unknown xref type: %s", context.PDFReader.XrefInformation.Type)
	}
}

func (context *SignContext) getLastObjectIDFromXref() (uint32, error) {
	xref := context.PDFReader.Xref()
	if len(xref) == 0 {
		return 0, fmt.Errorf("no xref entries found")
	}

	// Find highest used object ID
	var maxID uint32
	for _, entry := range xref {
		ptr := entry.Ptr()

		// TODO: Check if in use (&& entry.offset != 0)
		if ptr.GetID() > maxID {
			maxID = ptr.GetID()
		}
	}

	return maxID + 1, nil
}
