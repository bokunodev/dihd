package blocklist

import (
	"errors"
	"os"
	"slices"

	"github.com/bokunodev/dihd/blocklist/internal/trie"

	"golang.org/x/sys/unix"
)

type BlockList struct {
	slab []byte
	file *os.File
}

func New(slabfile string) (*BlockList, error) {
	f, err := os.Open(slabfile)
	if err != nil {
		return nil, err
	}

	i, err := f.Stat()
	if err != nil {
		return nil, err
	}

	slab, err := unix.Mmap(int(f.Fd()), 0, int(i.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	bl := &BlockList{slab: slab, file: f}
	return bl, nil
}

func (bl *BlockList) Close() error {
	return errors.Join(unix.Munmap(bl.slab), bl.Close())
}

func (bl *BlockList) Lookup(domain string) bool {
	return trie.Search(bl.slab, normalize(domain))
}

func normalize(domain string) []byte {
	word := []byte(domain)
	slices.Reverse(word)
	if word[0] != '.' {
		word = append([]byte{'.'}, word...)
	}

	return word
}
