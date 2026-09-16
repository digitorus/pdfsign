package sign

import (
	"bytes"
	"testing"

	"github.com/mattetti/filebuffer"
)

func TestWriteIncrXrefTable(t *testing.T) {
	// Test setup
	context := &SignContext{
		OutputBuffer: &filebuffer.Buffer{
			Buff: new(bytes.Buffer),
		},
		lastXrefID: 100,
		updatedXrefEntries: []xrefEntry{
			{ID: 50, Offset: 1234},
			{ID: 51, Offset: 5678},
		},
		newXrefEntries: []xrefEntry{
			{ID: 101, Offset: 9012},
			{ID: 102, Offset: 3456},
		},
	}

	// Execute test
	err := context.writeIncrXrefTable()
	if err != nil {
		t.Fatalf("writeIncrXrefTable failed: %v", err)
	}

	// Verify output
	expected := "xref\n" +
		"50 1\n" +
		"0000001234 00000 n\r\n" +
		"51 1\n" +
		"0000005678 00000 n\r\n" +
		"101 2\n" +
		"0000009012 00000 n\r\n" +
		"0000003456 00000 n\r\n"

	got := context.OutputBuffer.Buff.String()
	if got != expected {
		t.Errorf("writeIncrXrefTable output mismatch\ngot:\n%s\nwant:\n%s", got, expected)
	}
}
