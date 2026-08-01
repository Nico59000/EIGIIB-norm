package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eigiib.example/independent/p1distribution"
)

func main() {
	root := flag.String("root", ".", "repository root")
	policyPath := flag.String("policy", "", "P1-A8 policy path")
	outDir := flag.String("out-dir", "", "output directory")
	jsonOutput := flag.Bool("json", false, "emit JSON result")
	flag.Parse()
	if *policyPath == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "P1A8.DISTRIBUTION.FAILURE: --policy and --out-dir are required")
		os.Exit(2)
	}
	policy, err := p1distribution.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "P1A8.DISTRIBUTION.FAILURE: %v\n", err)
		os.Exit(2)
	}
	output, err := p1distribution.Build(*root, policy)
	if err == nil {
		err = p1distribution.WriteOutput(*outDir, policy, output)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "P1A8.DISTRIBUTION.FAILURE: %v\n", err)
		os.Exit(2)
	}
	if *jsonOutput {
		var release any
		_ = json.Unmarshal(output.Release, &release)
		result := map[string]any{"tool": "eigiib-p1-a8-distribution", "tool_version": "0.1.0", "publisher": "independent-go-stdlib", "release": release, "result": "conformant"}
		raw, _ := json.Marshal(result)
		fmt.Println(string(raw))
	}
}
