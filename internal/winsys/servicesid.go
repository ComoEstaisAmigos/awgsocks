package winsys

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

func ServiceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], u)
	}
	sum := sha1.Sum(buf)
	sid := "S-1-5-80"
	for i := 0; i < len(sum); i += 4 {
		sid += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(sum[i:]))
	}
	return sid
}

func ServiceAccount(name string) string {
	return `NT SERVICE\` + name
}
