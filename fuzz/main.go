package fuzz

import (
	"bytes"

	"plan9.io/encoding/plan9"
)

// Fuzz fuzzes fuzzy fuzzballs
func Fuzz(data []byte) int {
	_, err := plan9.Decode(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	return 1
}
