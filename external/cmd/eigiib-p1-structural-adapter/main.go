package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/external/p1structural"
)

func main() {
	input := flag.String("input", "", "input file")
	vectorID := flag.String("vector-id", "", "vector identifier")
	flag.Parse()
	if *input == "" || *vectorID == "" {
		fmt.Fprintln(os.Stderr, "input and vector-id are required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := p1structural.Evaluate(raw, *vectorID)
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
}
