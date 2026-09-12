package config

import "encoding/base64"

// decodeStdBase64 decodes a standard-encoding base64 string, matching the
// upstream parser use of base64.StdEncoding for key material.
func decodeStdBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
