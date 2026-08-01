package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/external/p1time"
)

func main() {
	root := flag.String("root", "..", "repository root")
	capsule := flag.String("capsule", "", "capsule path")
	flag.Parse()
	if *capsule == "" {
		fmt.Fprintln(os.Stderr, "missing --capsule")
		os.Exit(2)
	}
	result, err := p1time.Evaluate(*root, *capsule)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
