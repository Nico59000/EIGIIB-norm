package p1runner

import (
	"errors"
	"sort"
)

func validateSource(std, commit, report, env string) error {
	if std != standard || commit != sourceCommit || report != sourceReport || env != environment {
		return errors.New("source binding mismatch")
	}
	return nil
}

func validateRunnerRegistry(reg RunnerRegistry) (map[string]Runner, error) {
	if err := validateSource(reg.Standard, reg.SourceCommit, reg.SourceReport, reg.Environment); err != nil {
		return nil, err
	}
	if reg.RegistryID != "eigiib-p1-a20-runner-registry-v1" || reg.Sequence != 120 {
		return nil, errors.New("runner registry metadata mismatch")
	}
	ids := make([]string, len(reg.Runners))
	result := map[string]Runner{}
	for i, runner := range reg.Runners {
		ids[i] = runner.RunnerID
		if _, exists := result[runner.RunnerID]; exists {
			return nil, errors.New("duplicate runner id")
		}
		if runner.Status != "active" && runner.Status != "retired" && runner.Status != "quarantined" {
			return nil, errors.New("unknown runner status")
		}
		if runner.Generation < 1 || runner.AdmittedAtSequence > runner.ValidThroughSequence || !validHex64(runner.IdentitySHA256) {
			return nil, errors.New("invalid runner record")
		}
		result[runner.RunnerID] = runner
	}
	if !sort.StringsAreSorted(ids) {
		return nil, errors.New("runner registry order mismatch")
	}
	return result, nil
}

func validateToolchainRegistry(reg ToolchainRegistry) (map[string]ToolchainVersion, error) {
	if err := validateSource(reg.Standard, reg.SourceCommit, reg.SourceReport, reg.Environment); err != nil {
		return nil, err
	}
	if reg.RegistryID != "eigiib-p1-a20-toolchain-registry-v1" || reg.Sequence != 120 || reg.ToolchainID != "eigiib-verifier" {
		return nil, errors.New("toolchain registry metadata mismatch")
	}
	result := map[string]ToolchainVersion{}
	for _, item := range reg.Versions {
		if _, exists := result[item.Version]; exists {
			return nil, errors.New("duplicate toolchain version")
		}
		if item.State != "active" && item.State != "compatibility" && item.State != "candidate" && item.State != "retired" {
			return nil, errors.New("unknown toolchain state")
		}
		if item.OrdinaryFromSequence > item.OrdinaryThroughSequence || item.RollbackEligibleThroughSequence < item.OrdinaryThroughSequence || !validHex64(item.ArtifactSHA256) {
			return nil, errors.New("invalid toolchain record")
		}
		for platform, generations := range item.CompatibleRunnerGenerations {
			if platform != "linux" && platform != "macos" && platform != "windows" {
				return nil, errors.New("unknown compatibility platform")
			}
			if !sort.IntsAreSorted(generations) {
				return nil, errors.New("non-canonical generation set")
			}
			for _, generation := range generations {
				if generation < 1 {
					return nil, errors.New("invalid compatible generation")
				}
			}
		}
		result[item.Version] = item
	}
	active, ok := result[reg.ActiveVersion]
	if !ok || active.State != "active" {
		return nil, errors.New("active toolchain mismatch")
	}
	predecessor, ok := result[reg.PredecessorVersion]
	if !ok || predecessor.State != "compatibility" || reg.ActiveVersion == reg.PredecessorVersion {
		return nil, errors.New("predecessor toolchain mismatch")
	}
	return result, nil
}

func validateAuthorization(auth RollbackAuthorization) error {
	if err := validateSource(auth.Standard, auth.SourceCommit, auth.SourceReport, auth.Environment); err != nil {
		return err
	}
	if auth.AuthorizationID != "rollback-1.9.0-to-1.8.0-prod-v1" || auth.FromVersion != "1.9.0" || auth.ToVersion != "1.8.0" || auth.MaxUses != 1 {
		return errors.New("rollback authorization metadata mismatch")
	}
	if auth.NotBefore > auth.NotAfter || !validHex64(auth.ReasonSHA256) {
		return errors.New("invalid rollback authorization")
	}
	return nil
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
