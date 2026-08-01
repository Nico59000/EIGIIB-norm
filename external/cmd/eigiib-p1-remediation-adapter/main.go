package main

import (
	"eigiib.example/external/p1remediation"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "repository root")
	capsule := flag.String("capsule", "tests/fixtures/p1-a14/capsule.json", "capsule path")
	flag.Parse()
	path := *capsule
	if !filepath.IsAbs(path) {
		path = filepath.Join(*root, path)
	}
	result, err := p1remediation.Evaluate(*root, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := p1remediation.CanonicalResult(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(raw)
}
