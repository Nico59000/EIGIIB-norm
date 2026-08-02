package main

import (
	"eigiib.example/independent/p1durability"
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root")
	live := flag.Bool("live", false, "perform live readback")
	flag.Parse()
	r, e := p1durability.Run(*root, *live)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	b, e := p1durability.Encode(r)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}
