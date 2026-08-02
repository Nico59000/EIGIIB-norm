package p1durability

import "testing"

func TestFixtureRoute(t *testing.T) {
	r, e := Run("../..", false)
	if e != nil {
		t.Fatal(e)
	}
	if r.Route != "independent-go-stdlib" {
		t.Fatal(r.Route)
	}
	if len(ObjectNames()) != 5 {
		t.Fatal("object count")
	}
	if _, e = Encode(r); e != nil {
		t.Fatal(e)
	}
}
