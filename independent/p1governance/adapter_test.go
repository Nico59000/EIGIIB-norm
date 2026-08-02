package p1governance

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	root := filepath.Join("..", "..")
	r, e := Run(root)
	if e != nil {
		t.Fatal(e)
	}
	if r["overallResult"] != "conformant" {
		t.Fatal(r)
	}
}
func TestDeterministic(t *testing.T) {
	root := filepath.Join("..", "..")
	a, e := Run(root)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Run(root)
	if e != nil {
		t.Fatal(e)
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatal("non deterministic")
	}
}
