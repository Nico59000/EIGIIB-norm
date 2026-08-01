package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/external/p1negative"
)

func main() {
	input := flag.String("input", "", "input fixture")
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
	encoded, err := json.Marshal(p1negative.Evaluate(raw, *vectorID))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
}
