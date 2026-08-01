package p1release

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixture(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join(root, p))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	r := Evaluate(read("tests/fixtures/p1-a9/capsule.json"), read("tests/fixtures/p1-a8/expected-release.json"), read("tests/fixtures/p1-a9/release-public-key.pem"), read("tests/fixtures/p1-a9/ts-public-key.pem"))
	if !r.Accepted {
		t.Fatalf("rejected: %#v", r)
	}
}
func TestMutation(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join(root, p))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	c := read("tests/fixtures/p1-a9/capsule.json")
	c[len(c)/2] ^= 1
	r := Evaluate(c, read("tests/fixtures/p1-a8/expected-release.json"), read("tests/fixtures/p1-a9/release-public-key.pem"), read("tests/fixtures/p1-a9/ts-public-key.pem"))
	if r.Accepted {
		t.Fatal("mutation accepted")
	}
}
