package cachesnake

import (
	"crypto/rand"
)

// removes an element from a slice quickly. Changes the order of elements
func FastRemove[T any](s []T, i int) []T {
	var default_val T
	s[len(s)-1], s[i] = default_val, s[len(s)-1]
	return s[:len(s)-1]
}

// generate a random alphabetical lowercase string
func GenRandString(length int) string {
	str_bytes := make([]byte, length)
	rand.Read(str_bytes)

	for i, v := range str_bytes {
		str_bytes[i] = ((v % 26) + 97)
	}

	return string(str_bytes)
}
