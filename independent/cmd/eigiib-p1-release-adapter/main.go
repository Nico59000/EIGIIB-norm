package main

import (
	"eigiib.example/independent/p1release"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	capsule := flag.String("capsule", "", "capsule")
	release := flag.String("release", "", "release")
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
	r := p1release.Evaluate(read(*capsule), read(*release), read(*rk), read(*tk))
	json.NewEncoder(os.Stdout).Encode(r)
	if !r.Accepted {
		os.Exit(2)
	}
}
