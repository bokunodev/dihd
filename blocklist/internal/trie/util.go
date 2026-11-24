package trie

func boolToByte(b bool) uint8 {
	if b {
		return 1
	}

	return 0
}

func commonPrefixLenBytes(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
