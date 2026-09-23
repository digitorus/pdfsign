package verify

import (
	"bytes"
	"fmt"
)

// writeObj writes a classic PDF object definition to buf and returns its byte offset.
func writeObj(buf *bytes.Buffer, id int, body string) int64 {
	offset := int64(buf.Len())
	fmt.Fprintf(buf, "%d 0 obj\n%s\nendobj\n", id, body)
	return offset
}
