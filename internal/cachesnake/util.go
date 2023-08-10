package cachesnake

import (
	"crypto/rand"
)

func GenRandString(length int) string {
	str_bytes := make([]byte, length)
	rand.Read(str_bytes)

	for i, v := range str_bytes {
		str_bytes[i] = ((v % 26) + 97)
	}

	return string(str_bytes)
}
