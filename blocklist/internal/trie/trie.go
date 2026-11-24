package trie

import (
	"encoding/binary"
)

const headerSize = 8

type Node struct {
	children []*Node
	value    string
	end      bool
}

func (n *Node) Count() int {
	total := 0
	for _, c := range n.children {
		total += 1 + c.Count()
	}

	return total
}

func (n *Node) Size() int {
	total := 0
	for _, c := range n.children {
		total += headerSize
		total += len(c.value)
		total += c.Size()
	}

	return total
}

// Little-endian 64-bit header layout:
// [0]   value length (uint8)
// [1]   edge marking / end flag (uint8)
// [2:4] number of children (uint16)
// [4:8] offset to the first child (uint32)
// [8:n]  edge value bytes

func Marshal(root *Node) []byte {
	buf := make([]byte, headerSize+root.Size())[:0]

	buf = append(buf, uint8(len(root.value)))                               // 1: valLen
	buf = append(buf, boolToByte(root.end))                                 // 2: endFlag
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(root.children))) // 3: numChildren
	buf = binary.LittleEndian.AppendUint32(buf, uint32(headerSize))         // 4: firstChildOffset

	buf = root.marshalChildren(buf, headerSize)

	return buf
}

func (n *Node) marshalChildren(buf []byte, offset int) []byte {
	origTotalChildrenSize := offset
	for _, c := range n.children {
		origTotalChildrenSize += headerSize
		origTotalChildrenSize += len(c.value)
	}

	totalChildrenSize := origTotalChildrenSize
	for _, c := range n.children {
		buf = append(buf, uint8(len(c.value)))                               // 1: valLen
		buf = append(buf, boolToByte(c.end))                                 // 2: endFlag
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(c.children))) // 3: numChildren
		if len(c.children) > 0 {
			buf = binary.LittleEndian.AppendUint32(buf, uint32(totalChildrenSize)) // 4: firstChildOffset
		} else {
			buf = binary.LittleEndian.AppendUint32(buf, 0) // 4: firstChildOffset
		}

		buf = append(buf, []byte(c.value)...)
		totalChildrenSize += c.Size()
	}

	totalChildrenSize = origTotalChildrenSize
	for _, c := range n.children {
		buf = c.marshalChildren(buf, totalChildrenSize)
		totalChildrenSize += c.Size()
	}

	return buf
}

func Insert(current *Node, data string) {
	if data == "" {
		return
	}

	if len(current.children) == 0 {
		current.children = append(current.children, &Node{value: data, end: true})
		return
	}

	for _, c := range current.children {
		n := commonPrefixLenBytes([]byte(c.value), []byte(data))
		if n > 0 {
			oldEnd := c.end
			oldChildren := c.children
			trail := c.value[n:]
			rem := data[n:]

			c.value = c.value[:n]

			// Move the remainder of the split edge down so its old children stay anchored after trail.
			if len(trail) > 0 {
				c.end = false
				c.children = []*Node{{
					value:    trail,
					end:      oldEnd,
					children: oldChildren,
				}}
			} else {
				c.end = oldEnd
			}

			// If data ended right at c's new prefix, c itself is a complete entry.
			if len(rem) == 0 {
				c.end = true
				return
			}

			// Otherwise let insert compress rem against c's children
			Insert(c, rem)
			return
		}
	}

	current.children = append(current.children, &Node{value: data, end: true})
}

func Search(slab, word []byte) bool {
	if len(slab) < headerSize || len(word) == 0 {
		return false
	}

	rootHeader := binary.LittleEndian.Uint64(slab[:headerSize])
	rootChildCount := int((rootHeader >> 16) & 0xffff)
	rootChildOffset := int((rootHeader >> 32) & 0xffffffff)
	if rootChildCount == 0 {
		return false
	}

	offset := rootChildOffset
	count := rootChildCount
	pos := 0

	for pos < len(word) {
		if count <= 0 || offset < 0 || offset >= len(slab) {
			return false
		}

		cur := offset
		matched := false

		for i := 0; i < count; i++ {
			if cur+headerSize > len(slab) {
				return false
			}

			hdr := binary.LittleEndian.Uint64(slab[cur : cur+headerSize])
			valLen := int(hdr & 0xff)
			endFlag := ((hdr >> 8) & 0xff) != 0
			numChildren := int((hdr >> 16) & 0xffff)
			firstChildOffset := int((hdr >> 32) & 0xffffffff)

			entryEnd := cur + headerSize + valLen
			if entryEnd > len(slab) {
				return false
			}

			val := slab[cur+headerSize : entryEnd]
			common := commonPrefixLenBytes(val, word[pos:])

			if common > 0 {
				if common == len(val) {
					pos += common
					if pos == len(word) {
						return endFlag
					}
					if numChildren == 0 || firstChildOffset == 0 {
						return false
					}
					offset = firstChildOffset
					count = numChildren
					matched = true
					break
				}

				// Partial match inside a compressed edge: siblings don't extend this prefix further.
				return false
			}

			cur = entryEnd
		}

		if !matched {
			return false
		}
	}

	return false
}
