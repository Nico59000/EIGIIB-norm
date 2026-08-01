package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1transparency"
)

func main() {
	root := flag.String("root", ".", "repository root")
	capsule := flag.String("capsule", "tests/fixtures/p1-a12/capsule.json", "capsule path")
	flag.Parse()
	result, err := p1transparency.Evaluate(*root, *capsule)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
