package main

import (
	"eigiib.example/external/p1revocation"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "repository root")
	capsule := flag.String("capsule", "tests/fixtures/p1-a13/capsule.json", "capsule path")
	flag.Parse()
	path := *capsule
	if !filepath.IsAbs(path) {
		path = filepath.Join(*root, path)
	}
	result, err := p1revocation.Evaluate(*root, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := p1revocation.CanonicalResult(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(raw)
}
