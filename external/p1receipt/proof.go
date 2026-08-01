package p1receipt

import (
	"bytes"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

func decodeProof(raw []byte, mode cbor.EncMode) (int64, int64, [][]byte, string, string) {
	var value any
	if err := cbor.Unmarshal(raw, &value); err != nil {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	canonical, err := mode.Marshal(value)
	if err != nil {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	if !bytes.Equal(canonical, raw) {
		return 0, 0, nil, "cbor.nondeterministic", "receipt-proof"
	}
	array, ok := value.([]any)
	if !ok || len(array) != 3 {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	tree, ok := integer(array[0])
	if !ok {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	leaf, ok := integer(array[1])
	if !ok {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	pathValues, ok := array[2].([]any)
	if !ok {
		return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
	}
	path := make([][]byte, 0, len(pathValues))
	for _, item := range pathValues {
		sibling, ok := item.([]byte)
		if !ok || len(sibling) != sha256.Size {
			return 0, 0, nil, "receipt.invalid-proof", "receipt-proof"
		}
		path = append(path, sibling)
	}
	return tree, leaf, path, "", ""
}

func inclusionRoot(entry []byte, treeSize, leafIndex int64, path [][]byte) ([]byte, bool, bool) {
	expected, coordinatesOK := expectedPathLength(treeSize, leafIndex)
	if !coordinatesOK {
		return nil, false, false
	}
	if len(path) != expected {
		return nil, false, true
	}
	leafInput := append([]byte{0}, entry...)
	leaf := sha256.Sum256(leafInput)
	current := append([]byte(nil), leaf[:]...)
	index := leafIndex
	size := treeSize
	for _, sibling := range path {
		node := make([]byte, 65)
		node[0] = 1
		if index%2 == 1 {
			copy(node[1:33], sibling)
			copy(node[33:], current)
		} else {
			copy(node[1:33], current)
			copy(node[33:], sibling)
		}
		sum := sha256.Sum256(node)
		current = append(current[:0], sum[:]...)
		index /= 2
		size = (size + 1) / 2
		_ = size
	}
	return current, true, true
}
func expectedPathLength(treeSize, leafIndex int64) (int, bool) {
	if treeSize < 1 || leafIndex < 0 || leafIndex >= treeSize {
		return 0, false
	}
	count := 0
	size, index := treeSize, leafIndex
	for size > 1 {
		if index%2 == 1 || index < size-1 {
			count++
		}
		index /= 2
		size = (size + 1) / 2
	}
	return count, true
}
