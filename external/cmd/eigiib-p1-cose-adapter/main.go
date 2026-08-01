package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/external/p1cose"
)

func main() {
	input := flag.String("input", "", "COSE_Sign1 input file")
	publicKey := flag.String("public-key", "", "issuer Ed25519 public key")
	vectorID := flag.String("vector-id", "", "vector identifier")
	flag.Parse()
	if *input == "" || *publicKey == "" || *vectorID == "" {
		fmt.Fprintln(os.Stderr, "input, public-key and vector-id are required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	key, err := os.ReadFile(*publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := p1cose.Evaluate(raw, key, *vectorID)
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
}
