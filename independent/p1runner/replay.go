package p1runner

func decisionForRoute(
	route Route,
	runnerReg RunnerRegistry,
	toolchainReg ToolchainRegistry,
	runners map[string]Runner,
	versions map[string]ToolchainVersion,
	auths map[string]RollbackAuthorization,
	used map[string]bool,
) (map[string]any, error) {
	runnerSHA, err := shaCanonical(runnerReg)
	if err != nil {
		return nil, err
	}
	toolchainSHA, err := shaCanonical(toolchainReg)
	if err != nil {
		return nil, err
	}
	var authorization any
	if route.RollbackAuthorizationID != nil {
		authorization = *route.RollbackAuthorizationID
	}
	base := map[string]any{
		"routeId":                 route.RouteID,
		"sequence":                route.Sequence,
		"environment":             route.Environment,
		"runnerId":                route.RunnerID,
		"toolchainVersion":        route.ToolchainVersion,
		"mode":                    route.Mode,
		"rollbackAuthorizationId": authorization,
		"sourceP1A19F2Commit":     sourceCommit,
		"sourceP1A19ReportSha256": sourceReport,
		"runnerRegistrySha256":    runnerSHA,
		"toolchainRegistrySha256": toolchainSHA,
	}
	finish := func(decision, reason string) (map[string]any, error) {
		result := map[string]any{}
		for key, value := range base {
			result[key] = value
		}
		result["decision"] = decision
		result["reason"] = reason
		digest, err := shaCanonical(result)
		if err != nil {
			return nil, err
		}
		result["decisionSha256"] = digest
		return result, nil
	}

	if route.Environment != environment {
		return finish("rejected", "environment-mismatch")
	}
	runner, ok := runners[route.RunnerID]
	if !ok {
		return finish("rejected", "unknown-runner")
	}
	if route.RunnerIdentitySHA256 != runner.IdentitySHA256 {
		return finish("rejected", "runner-identity-mismatch")
	}
	if runner.Status != "active" {
		return finish("rejected", "runner-status-"+runner.Status)
	}
	if route.Sequence < runner.AdmittedAtSequence {
		return finish("rejected", "runner-not-yet-admitted")
	}
	if route.Sequence > runner.ValidThroughSequence {
		return finish("rejected", "runner-admission-expired")
	}
	toolchain, ok := versions[route.ToolchainVersion]
	if !ok {
		return finish("rejected", "unknown-toolchain")
	}
	if route.ToolchainArtifactSHA256 != toolchain.ArtifactSHA256 {
		return finish("rejected", "toolchain-artifact-mismatch")
	}
	if toolchain.State != "active" && toolchain.State != "compatibility" {
		return finish("rejected", "toolchain-state-"+toolchain.State)
	}
	if !containsInt(toolchain.CompatibleRunnerGenerations[runner.Platform], runner.Generation) {
		return finish("rejected", "incompatible-runner-toolchain")
	}
	if route.Mode == "normal" {
		if route.RollbackAuthorizationID != nil {
			return finish("rejected", "unexpected-rollback-authorization")
		}
		if route.Sequence < toolchain.OrdinaryFromSequence || route.Sequence > toolchain.OrdinaryThroughSequence {
			return finish("rejected", "compatibility-window-closed")
		}
		return finish("accepted", "ordinary-admission-and-compatibility-window-satisfied")
	}
	if route.Mode != "rollback" {
		return finish("rejected", "unknown-execution-mode")
	}
	if route.RollbackAuthorizationID == nil {
		return finish("rejected", "rollback-authorization-required")
	}
	authorizationID := *route.RollbackAuthorizationID
	if used[authorizationID] {
		return finish("rejected", "rollback-authorization-replayed")
	}
	auth, ok := auths[authorizationID]
	if !ok {
		return finish("rejected", "unknown-rollback-authorization")
	}
	if route.ToolchainVersion != toolchainReg.PredecessorVersion {
		return finish("rejected", "rollback-target-is-not-registered-predecessor")
	}
	if auth.FromVersion != toolchainReg.ActiveVersion || auth.ToVersion != route.ToolchainVersion {
		return finish("rejected", "rollback-lineage-mismatch")
	}
	if auth.RunnerID != route.RunnerID || auth.Environment != route.Environment {
		return finish("rejected", "rollback-authorization-binding-mismatch")
	}
	if route.Sequence < auth.NotBefore || route.Sequence > auth.NotAfter {
		return finish("rejected", "rollback-authorization-window-closed")
	}
	if route.Sequence > toolchain.RollbackEligibleThroughSequence {
		return finish("rejected", "toolchain-rollback-window-closed")
	}
	used[authorizationID] = true
	return finish("accepted", "signed-single-use-rollback-authorized")
}
