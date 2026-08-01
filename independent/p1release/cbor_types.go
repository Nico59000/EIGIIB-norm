package p1release

import "errors"

type cborTag struct {
	Number uint64
	Value  any
}

type cborDecoder struct {
	raw []byte
	pos int
}

var errNonDeterministic = errors.New("non-deterministic CBOR encoding")
