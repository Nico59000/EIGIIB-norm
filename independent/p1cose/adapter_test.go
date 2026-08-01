package p1cose

import (
	"encoding/base64"
	"testing"
)

const positiveB64 = "0oRY16UBJwNwYXBwbGljYXRpb24vY2JvcgRYIGbOK1AnnQ+VWi5zQ0VgQ55OR7+m1vNl+Kg0k1EOl/RHD6IBeCNodHRwczovL2VpZ2lpYi5leGFtcGxlL3AxLWEzL2lzc3VlcgJ4UXVybjplaWdpaWI6cDEtYTI6ZGQxNGM3NTU2ZWEyNjFjZWUwM2M0MDYxNTM2ODUxMWJmOTM2MGU1ZDdlYWU3NjQ4MDRkN2I0MjZmNGVkNmRhNBB4IGFwcGxpY2F0aW9uL3NjaXR0LXN0YXRlbWVudCtjb3NloFhso2VieXRlcxkPQ2ZzaGEyNTZYIN0Ux1VuomHO4DxAYVNoURv5Ng5dfq52SATXtCb07W2kaW1lZGlhVHlwZXgtYXBwbGljYXRpb24vdm5kLmRldi5zaWdzdG9yZS5idW5kbGUudjAuMytqc29uWED1eJtfGiAh17joQhjXgBKiiJTwm+ol7/7KNtb/CmRIQ5ClEOybsmBqR4x0KxMuAva57w+Qux/HzbK7/sZ1FM8F"

const issuerKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8c4vONbzQKUWC66YwvR2yJ8gZwhBpJi7pP7x85LTsWs=\n-----END PUBLIC KEY-----\n"

func positiveBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(positiveB64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateProtected(t *testing.T, raw []byte, mutate func(map[any]any)) []byte {
	t.Helper()
	value, err := decodeCBOR(raw)
	if err != nil {
		t.Fatal(err)
	}
	tag := value.(cborTag)
	array := tag.Value.([]any)
	protected, err := decodeCBOR(array[0].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	mapping := protected.(map[any]any)
	mutate(mapping)
	array[0], err = encodeCBOR(mapping)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeCBOR(tag)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPositive(t *testing.T) {
	result := Evaluate(positiveBytes(t), []byte(issuerKey), "positive")
	if !result.Accepted || result.ErrorClass != nil || result.Boundary != "cose-signature" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNonMinimalTag(t *testing.T) {
	raw := positiveBytes(t)
	mutated := append([]byte{0xd9, 0x00, 0x12}, raw[1:]...)
	result := Evaluate(mutated, []byte(issuerKey), "nonminimal")
	if result.ErrorClass == nil || *result.ErrorClass != "cbor.nondeterministic" || result.Boundary != "cbor-sign1" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestWrongTag(t *testing.T) {
	raw := append([]byte(nil), positiveBytes(t)...)
	raw[0] = 0xd1
	result := Evaluate(raw, []byte(issuerKey), "wrong-tag")
	if result.ErrorClass == nil || *result.ErrorClass != "cose.invalid-structure" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	raw := mutateProtected(t, positiveBytes(t), func(mapping map[any]any) {
		mapping[int64(1)] = int64(-7)
	})
	result := Evaluate(raw, []byte(issuerKey), "alg")
	if result.ErrorClass == nil || *result.ErrorClass != "cose.unsupported-header" || result.Boundary != "cose-protected-header" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestMalformedCritical(t *testing.T) {
	raw := mutateProtected(t, positiveBytes(t), func(mapping map[any]any) {
		mapping[int64(2)] = "alg"
	})
	result := Evaluate(raw, []byte(issuerKey), "crit")
	if result.ErrorClass == nil || *result.ErrorClass != "cose.invalid-structure" || result.Boundary != "cose-protected-header" {
		t.Fatalf("unexpected result: %#v", result)
	}
}
