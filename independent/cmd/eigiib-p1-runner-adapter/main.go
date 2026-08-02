package main

import (
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1runner"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	report, err := p1runner.LoadAndReport(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
