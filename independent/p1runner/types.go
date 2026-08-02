package p1runner

import "encoding/json"

const (
	standard     = "EIGIIB-P1-A20-CONFORMANCE-1.0"
	sourceCommit = "66b25d4f27ded3e273922f9fdcf80b9c88c8c808"
	sourceReport = "8008f0eb90328a4ff01f1bd4a594f1f7417ecbd3f5c68efdcf07bf801be62c2a"
	environment  = "p1-a20-fixture-production"
	boundary     = "signed-runner-admission-toolchain-succession-declared-compatibility-window-single-use-rollback-replay-closure"
)

type Envelope struct {
	KeyID           string          `json:"keyId"`
	Payload         json.RawMessage `json:"payload"`
	PayloadSHA256   string          `json:"payloadSha256"`
	SignatureBase64 string          `json:"signatureBase64"`
}

type BundleIndex struct {
	Environment                string   `json:"environment"`
	RollbackAuthorizationFiles []string `json:"rollbackAuthorizationFiles"`
	RouteFiles                 []string `json:"routeFiles"`
	RunnerRegistryFile         string   `json:"runnerRegistryFile"`
	SourceCommit               string   `json:"sourceP1A19F2Commit"`
	SourceReport               string   `json:"sourceP1A19ReportSha256"`
	Standard                   string   `json:"standard"`
	ToolchainRegistryFile      string   `json:"toolchainRegistryFile"`
}

type Bundle struct {
	Environment                  string
	Routes                       []Route
	SignedRollbackAuthorizations []Envelope
	SignedRunnerRegistry         Envelope
	SignedToolchainRegistry      Envelope
	SourceCommit                 string
	SourceReport                 string
	Standard                     string
}

type RunnerRegistry struct {
	Environment  string   `json:"environment"`
	RegistryID   string   `json:"registryId"`
	Runners      []Runner `json:"runners"`
	Sequence     int      `json:"sequence"`
	SourceCommit string   `json:"sourceP1A19F2Commit"`
	SourceReport string   `json:"sourceP1A19ReportSha256"`
	Standard     string   `json:"standard"`
}

type Runner struct {
	AdmittedAtSequence   int     `json:"admittedAtSequence"`
	Architecture         string  `json:"architecture"`
	Generation           int     `json:"generation"`
	IdentitySHA256       string  `json:"identitySha256"`
	Platform             string  `json:"platform"`
	RunnerID             string  `json:"runnerId"`
	Status               string  `json:"status"`
	SupersededBy         *string `json:"supersededBy"`
	ValidThroughSequence int     `json:"validThroughSequence"`
}

type ToolchainRegistry struct {
	ActiveVersion      string             `json:"activeVersion"`
	Environment        string             `json:"environment"`
	PredecessorVersion string             `json:"predecessorVersion"`
	RegistryID         string             `json:"registryId"`
	Sequence           int                `json:"sequence"`
	SourceCommit       string             `json:"sourceP1A19F2Commit"`
	SourceReport       string             `json:"sourceP1A19ReportSha256"`
	Standard           string             `json:"standard"`
	ToolchainID        string             `json:"toolchainId"`
	Versions           []ToolchainVersion `json:"versions"`
}

type ToolchainVersion struct {
	ArtifactSHA256                  string           `json:"artifactSha256"`
	CompatibleRunnerGenerations     map[string][]int `json:"compatibleRunnerGenerations"`
	OrdinaryFromSequence            int              `json:"ordinaryFromSequence"`
	OrdinaryThroughSequence         int              `json:"ordinaryThroughSequence"`
	ReleaseSequence                 int              `json:"releaseSequence"`
	RollbackEligibleThroughSequence int              `json:"rollbackEligibleThroughSequence"`
	State                           string           `json:"state"`
	Version                         string           `json:"version"`
}

type RollbackAuthorization struct {
	AuthorizationID string `json:"authorizationId"`
	Environment     string `json:"environment"`
	FromVersion     string `json:"fromVersion"`
	MaxUses         int    `json:"maxUses"`
	NotAfter        int    `json:"notAfterSequence"`
	NotBefore       int    `json:"notBeforeSequence"`
	ReasonSHA256    string `json:"reasonSha256"`
	RunnerID        string `json:"runnerId"`
	SourceCommit    string `json:"sourceP1A19F2Commit"`
	SourceReport    string `json:"sourceP1A19ReportSha256"`
	Standard        string `json:"standard"`
	ToVersion       string `json:"toVersion"`
}

type Route struct {
	Environment             string         `json:"environment"`
	ExpectedDecision        map[string]any `json:"expectedDecision"`
	Mode                    string         `json:"mode"`
	RollbackAuthorizationID *string        `json:"rollbackAuthorizationId"`
	RouteID                 string         `json:"routeId"`
	RunnerID                string         `json:"runnerId"`
	RunnerIdentitySHA256    string         `json:"runnerIdentitySha256"`
	Sequence                int            `json:"sequence"`
	ToolchainArtifactSHA256 string         `json:"toolchainArtifactSha256"`
	ToolchainVersion        string         `json:"toolchainVersion"`
}
