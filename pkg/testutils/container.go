package testutils

import (
	"bytes"
	"io"
	"strings"
)

func ReadExecOutput(reader io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(reader)
	output := buf.Bytes()

	var result bytes.Buffer
	for len(output) > 0 {
		if len(output) < 8 {
			// If less than 8 bytes, just append what's left
			result.Write(output)
			break
		}
		// Read the payload size from bytes 4-7 (big-endian)
		payloadSize := int(output[4])<<24 | int(output[5])<<16 | int(output[6])<<8 | int(output[7])
		if payloadSize == 0 || len(output) < 8+payloadSize {
			// Invalid header or incomplete payload, return what we have
			result.Write(output[8:])
			break
		}
		// Extract payload
		result.Write(output[8 : 8+payloadSize])
		output = output[8+payloadSize:]
	}
	return strings.TrimSpace(result.String())
}
