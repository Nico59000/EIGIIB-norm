package main

import (
	"eigiib.example/external/p1release"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	c := flag.String("capsule", "", "capsule")
	r := flag.String("release", "", "release")
	rk := flag.String("release-key", "", "release key")
	tk := flag.String("ts-key", "", "ts key")
	flag.Parse()
	read := func(p string) []byte {
		b, e := os.ReadFile(p)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		return b
	}
	out := p1release.Evaluate(read(*c), read(*r), read(*rk), read(*tk))
	json.NewEncoder(os.Stdout).Encode(out)
	if !out.Accepted {
		os.Exit(2)
	}
}
