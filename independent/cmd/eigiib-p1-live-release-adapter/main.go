package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1liverelease"
)

func main() {
	root := flag.String("root", ".", "repository root")
	live := flag.Bool("live", false, "perform public GitHub readback")
	flag.Parse()
	portable, err := p1liverelease.Validate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *live {
		if err := p1liverelease.ValidateLive(portable); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	result := p1liverelease.Result{Route: "independent-go-stdlib", Portable: portable}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
