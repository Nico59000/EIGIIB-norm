package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1authorization"
)

func main() {
	root := flag.String("root", ".", "repository root")
	capsule := flag.String("capsule", "", "capsule path")
	flag.Parse()
	if *capsule == "" {
		fmt.Fprintln(os.Stderr, "missing --capsule")
		os.Exit(2)
	}
	result, err := p1authorization.Evaluate(*root, *capsule)
	if err != nil {
		fmt.Fprintln(os.Stderr, "P1A10.INDEPENDENT.FAILURE:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
