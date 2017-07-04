package sign

import (
	"fmt"
	"strings"
)

func (context *SignContext) updateByteRange() error {
	// Get current filesize. Easier than what should be the current size.
	// @todo: find out of this is safe.
	output_file_stat, _ := context.OutputFile.Stat()

	// Don't count last newline as file length.
	output_file_size := output_file_stat.Size() - 1

	// Calculate ByteRange values to replace them.
	context.ByteRangeValues = make([]int64, 4)

	// Signature ByteRange part 1 start byte is always byte 0.
	context.ByteRangeValues[0] = int64(0)

	// Signature ByteRange part 1 length always stops at the actual signature start byte.
	context.ByteRangeValues[1] = context.SignatureContentsStartByte

	// Signature ByteRange part 2 start byte directly starts after the actual signature.
	context.ByteRangeValues[2] = context.ByteRangeValues[1] + int64(signatureMaxLength)

	// Signature ByteRange part 2 length is everything else of the file.
	context.ByteRangeValues[3] = output_file_size - context.ByteRangeValues[2]

	new_byte_range := fmt.Sprintf("/ByteRange[%d %d %d %d]", context.ByteRangeValues[0], context.ByteRangeValues[1], context.ByteRangeValues[2], context.ByteRangeValues[3])

	// Make sure our ByteRange string didn't shrink in length.
	new_byte_range += strings.Repeat(" ", len(signatureByteRangePlaceholder)-len(new_byte_range))

	// Seek to ByteRange position in file.
	context.OutputFile.Seek(context.ByteRangeStartByte, 0)

	// Write new ByteRange.
	if _, err := context.OutputFile.Write([]byte(new_byte_range)); err != nil {
		return err
	}

	return nil
}
