package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1registry"
)

func main() {
	root := flag.String("root", ".", "repository root")
	live := flag.Bool("live", false, "perform public live registry readback")
	flag.Parse()

	var (
		result p1registry.PortableResult
		err    error
	)
	if *live {
		result, err = p1registry.LivePublic(*root)
	} else {
		result, err = p1registry.ValidateFixture(*root)
	}
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
