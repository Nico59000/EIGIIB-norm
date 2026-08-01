package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	"eigiib.example/independent/p1verify"
)

func main() {
	root := flag.String("root", ".", "repository root")
	pretty := flag.Bool("pretty", false, "pretty JSON")
	expected := flag.String("expected", "", "optional expected result JSON")
	flag.Parse()

	result := p1verify.Verify(*root)
	if *expected != "" {
		raw, err := os.ReadFile(*expected)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var want p1verify.Result
		if err := json.Unmarshal(raw, &want); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !reflect.DeepEqual(result, want) {
			fmt.Fprintln(os.Stderr, "independent verifier result differs from expected canonical result")
			os.Exit(1)
		}
	}

	var raw []byte
	var err error
	if *pretty {
		raw, err = json.MarshalIndent(result, "", "  ")
	} else {
		raw, err = json.Marshal(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(raw))
	if result.EndToEndResult != "conformant" {
		os.Exit(1)
	}
}
