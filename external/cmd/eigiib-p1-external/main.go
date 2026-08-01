package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	"eigiib.example/external/bridge"
)

func main() {
	root := flag.String("root", ".", "repository root")
	expected := flag.String("expected", "", "optional expected result JSON")
	pretty := flag.Bool("pretty", false, "pretty JSON")
	flag.Parse()

	result := bridge.Verify(*root)
	if *expected != "" {
		raw, err := os.ReadFile(*expected)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var wanted bridge.Result
		if err := json.Unmarshal(raw, &wanted); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !reflect.DeepEqual(result, wanted) {
			fmt.Fprintln(os.Stderr, "external native bridge result differs from expected canonical result")
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
