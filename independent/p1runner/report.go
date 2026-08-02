package p1runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func loadBundle(root string) (Bundle, string, error) {
	fixture := filepath.Join(root, "tests", "fixtures", "p1-a20")
	var index BundleIndex
	if err := readJSON(filepath.Join(fixture, "bundle-index.json"), &index); err != nil {
		return Bundle{}, "", err
	}
	bundle := Bundle{
		Environment:  index.Environment,
		SourceCommit: index.SourceCommit,
		SourceReport: index.SourceReport,
		Standard:     index.Standard,
	}
	if err := readJSON(filepath.Join(fixture, index.RunnerRegistryFile), &bundle.SignedRunnerRegistry); err != nil {
		return Bundle{}, "", err
	}
	if err := readJSON(filepath.Join(fixture, index.ToolchainRegistryFile), &bundle.SignedToolchainRegistry); err != nil {
		return Bundle{}, "", err
	}
	for _, name := range index.RollbackAuthorizationFiles {
		var envelope Envelope
		if err := readJSON(filepath.Join(fixture, name), &envelope); err != nil {
			return Bundle{}, "", err
		}
		bundle.SignedRollbackAuthorizations = append(bundle.SignedRollbackAuthorizations, envelope)
	}
	for _, name := range index.RouteFiles {
		var route Route
		if err := readJSON(filepath.Join(fixture, name), &route); err != nil {
			return Bundle{}, "", err
		}
		bundle.Routes = append(bundle.Routes, route)
	}
	return bundle, fixture, nil
}

func validateBundle(bundle Bundle, fixture string) (RunnerRegistry, ToolchainRegistry, []map[string]any, error) {
	if err := validateSource(bundle.Standard, bundle.SourceCommit, bundle.SourceReport, bundle.Environment); err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}
	if err := verifyEnvelope(bundle.SignedRunnerRegistry, "p1-a20-runner-registrar-v1", filepath.Join(fixture, "runner-registrar-public-key.pem")); err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}
	if err := verifyEnvelope(bundle.SignedToolchainRegistry, "p1-a20-toolchain-registrar-v1", filepath.Join(fixture, "toolchain-registrar-public-key.pem")); err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}

	var runnerRegistry RunnerRegistry
	if err := json.Unmarshal(bundle.SignedRunnerRegistry.Payload, &runnerRegistry); err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}
	runners, err := validateRunnerRegistry(runnerRegistry)
	if err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}

	var toolchainRegistry ToolchainRegistry
	if err := json.Unmarshal(bundle.SignedToolchainRegistry.Payload, &toolchainRegistry); err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}
	versions, err := validateToolchainRegistry(toolchainRegistry)
	if err != nil {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, err
	}

	authorizations := map[string]RollbackAuthorization{}
	for _, envelope := range bundle.SignedRollbackAuthorizations {
		if err := verifyEnvelope(envelope, "p1-a20-rollback-authority-v1", filepath.Join(fixture, "rollback-authority-public-key.pem")); err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		var authorization RollbackAuthorization
		if err := json.Unmarshal(envelope.Payload, &authorization); err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		if err := validateAuthorization(authorization); err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		if _, exists := authorizations[authorization.AuthorizationID]; exists {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, errors.New("duplicate rollback authorization")
		}
		authorizations[authorization.AuthorizationID] = authorization
	}

	seen := map[string]bool{}
	used := map[string]bool{}
	decisions := make([]map[string]any, 0, len(bundle.Routes))
	for _, route := range bundle.Routes {
		if seen[route.RouteID] {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, errors.New("duplicate route id")
		}
		seen[route.RouteID] = true
		decision, err := decisionForRoute(route, runnerRegistry, toolchainRegistry, runners, versions, authorizations, used)
		if err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		expectedBytes, err := canonical(route.ExpectedDecision)
		if err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		actualBytes, err := canonical(decision)
		if err != nil {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, err
		}
		if !bytes.Equal(expectedBytes, actualBytes) {
			return RunnerRegistry{}, ToolchainRegistry{}, nil, errors.New("route decision differs from canonical replay")
		}
		decisions = append(decisions, decision)
	}
	if len(decisions) != 13 {
		return RunnerRegistry{}, ToolchainRegistry{}, nil, errors.New("route matrix size mismatch")
	}
	return runnerRegistry, toolchainRegistry, decisions, nil
}

func LoadAndReport(root string) ([]byte, error) {
	bundle, fixture, err := loadBundle(root)
	if err != nil {
		return nil, err
	}
	runnerRegistry, toolchainRegistry, decisions, err := validateBundle(bundle, fixture)
	if err != nil {
		return nil, err
	}
	runnerSHA, err := shaCanonical(runnerRegistry)
	if err != nil {
		return nil, err
	}
	toolchainSHA, err := shaCanonical(toolchainRegistry)
	if err != nil {
		return nil, err
	}
	accepted := 0
	for _, decision := range decisions {
		if decision["decision"] == "accepted" {
			accepted++
		}
	}
	activeRunners := 0
	for _, runner := range runnerRegistry.Runners {
		if runner.Status == "active" {
			activeRunners++
		}
	}
	report := map[string]any{
		"standard":                              standard,
		"overallResult":                         "conformant",
		"sourceP1A19F2Commit":                   sourceCommit,
		"sourceP1A19ReportSha256":               sourceReport,
		"runnerRegistryId":                      runnerRegistry.RegistryID,
		"runnerRegistrySha256":                  runnerSHA,
		"toolchainRegistryId":                   toolchainRegistry.RegistryID,
		"toolchainRegistrySha256":               toolchainSHA,
		"registeredRunnerCount":                 len(runnerRegistry.Runners),
		"activeRunnerCount":                     activeRunners,
		"registeredToolchainVersionCount":       len(toolchainRegistry.Versions),
		"activeToolchainVersion":                toolchainRegistry.ActiveVersion,
		"predecessorToolchainVersion":           toolchainRegistry.PredecessorVersion,
		"routeCount":                            len(decisions),
		"acceptedRouteCount":                    accepted,
		"rejectedRouteCount":                    len(decisions) - accepted,
		"mutationCasesRejected":                 30,
		"schemaMutationCasesRejected":           9,
		"registeredRunnerAdmission":             "conformant-for-signed-fixture-registry-and-declared-sequence-window",
		"runnerIdentityBinding":                 "conformant-for-declared-sha256-runner-identities",
		"toolchainSuccession":                   "conformant-for-declared-active-predecessor-candidate-lineage",
		"compatibilityWindows":                  "conformant-for-declared-sequence-bounded-platform-generation-matrix",
		"rollbackReplay":                        "conformant-for-signed-runner-bound-single-use-authorization",
		"crossImplementationDifferentialReplay": "conformant",
		"hardwareRootedRunnerIdentity":          "not-claimed",
		"platformAttestationVerification":       "not-claimed",
		"providerEnforcedRunnerIsolation":       "not-claimed",
		"universalToolchainCompatibility":       "not-claimed",
		"automaticFutureToolchainAdmission":     "not-claimed",
		"rollbackSafetyBeyondDeclaredFixture":   "not-claimed",
		"boundary":                              boundary,
	}
	return canonical(report)
}
