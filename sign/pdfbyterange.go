package sign

import (
	"fmt"
	"strings"
)

func (context *SignContext) updateByteRange() error {
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	output_file_size := int64(context.OutputBuffer.Buff.Len())

	// Calculate ByteRange values to replace them.
	context.ByteRangeValues = make([]int64, 4)

	// Signature ByteRange part 1 start byte is always byte 0.
	context.ByteRangeValues[0] = int64(0)

	// Signature ByteRange part 1 length always stops at the actual signature start byte.
	context.ByteRangeValues[1] = context.SignatureContentsStartByte - 1

	// Signature ByteRange part 2 start byte directly starts after the actual signature.
	context.ByteRangeValues[2] = context.ByteRangeValues[1] + 1 + int64(context.SignatureMaxLength) + 1

	// Signature ByteRange part 2 length is everything else of the file.
	context.ByteRangeValues[3] = output_file_size - context.ByteRangeValues[2]

	new_byte_range := fmt.Sprintf("/ByteRange[%d %d %d %d]", context.ByteRangeValues[0], context.ByteRangeValues[1], context.ByteRangeValues[2], context.ByteRangeValues[3])

	// Make sure our ByteRange string didn't shrink in length.
	new_byte_range += strings.Repeat(" ", len(signatureByteRangePlaceholder)-len(new_byte_range))

	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return err
	}
	file_content := context.OutputBuffer.Buff.Bytes()

	if _, err := context.OutputBuffer.Write(file_content[:context.ByteRangeStartByte]); err != nil {
		return err
	}

	// Write new ByteRange.
	if _, err := context.OutputBuffer.Write([]byte(new_byte_range)); err != nil {
		return err
	}

	if _, err := context.OutputBuffer.Write(file_content[context.ByteRangeStartByte+int64(len(new_byte_range)):]); err != nil {
		return err
	}

	return nil
}
