package p1remediation

import independent "eigiib.example/independent/p1remediation"

func Evaluate(root, capsulePath string) (map[string]any, error) {
	return independent.EvaluateWithVerifier(root, capsulePath, verifyCOSE)
}

func CanonicalResult(result map[string]any) ([]byte, error) {
	return independent.CanonicalResult(result)
}
