package main

import (
	"eigiib.example/independent/p1receipt"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	input := flag.String("input", "", "input carrier")
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
	encoded, err := json.Marshal(p1receipt.Evaluate(raw, *vectorID))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
}
