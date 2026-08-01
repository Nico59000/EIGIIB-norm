package p1transparency

import "testing"

func TestEvaluate(t *testing.T) {
	result, err := Evaluate("../..", "../../tests/fixtures/p1-a12/capsule.json")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Route != Route || result.EquivocationResult != "detected-and-quarantined" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
