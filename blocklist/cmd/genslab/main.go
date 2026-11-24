package main

import (
	"bufio"
	"flag"
	"os"

	"github.com/bokunodev/dihd/blocklist/internal/trie"
)

func main() {
	hostfile := flag.String("hostfile", "", "path to text file containing list of domain names")
	outfile := flag.String("out", "", "path to output file")
	flag.Parse()

	if *hostfile == "" || *outfile == "" {
		flag.PrintDefaults()
		os.Exit(2) // invalid argument
	}

	root := &trie.Node{}

	f, err := os.Open(*hostfile)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	scn := bufio.NewScanner(f)
	for scn.Scan() {
		if err = scn.Err(); err != nil {
			panic(err)
		}

		domain := scn.Text()
		if domain == "" {
			continue
		}

		trie.Insert(root, domain)
	}

	buf := trie.Marshal(root)
	err = os.WriteFile(*outfile, buf, os.ModePerm&0o644)
	if err != nil {
		panic(err)
	}
}
