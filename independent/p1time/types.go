package p1time

type Identity struct {
	Algorithm string `json:"algorithm"`
	Bytes     int    `json:"bytes"`
	Digest    string `json:"digest"`
}

type DataCarrier struct {
	Data     string   `json:"data"`
	Identity Identity `json:"identity"`
}

type KeyCarrier struct {
	ID   string   `json:"id,omitempty"`
	Path string   `json:"path"`
	SPKI Identity `json:"spki"`
}

type FileCarrier struct {
	Identity Identity `json:"identity"`
	Path     string   `json:"path"`
}

type SourceAuthorization struct {
	AuthorizationCapsule          FileCarrier `json:"authorizationCapsule"`
	AuthorizationReport           FileCarrier `json:"authorizationReport"`
	RecoveredAuthorizationPayload Identity    `json:"recoveredAuthorizationPayload"`
	ReleaseDescriptor             Identity    `json:"releaseDescriptor"`
	ReleaseID                     string      `json:"releaseId"`
}

type PolicyCarrier struct {
	Envelope DataCarrier `json:"envelope"`
	Payload  DataCarrier `json:"payload"`
}

type ObservationCarrier struct {
	Envelope         DataCarrier `json:"envelope"`
	ExpectedDecision string      `json:"expectedDecision"`
	ID               string      `json:"id"`
	Payload          DataCarrier `json:"payload"`
}

type Capsule struct {
	ClaimBoundary struct {
		DoesNotImply []string `json:"doesNotImply"`
	} `json:"claimBoundary"`
	Observations        []ObservationCarrier `json:"observations"`
	Policy              PolicyCarrier        `json:"policy"`
	Profile             string               `json:"profile"`
	SourceAuthorization SourceAuthorization  `json:"sourceAuthorization"`
	Standard            string               `json:"standard"`
	TimestampAuthority  KeyCarrier           `json:"timestampAuthority"`
	TimeTrustRoot       KeyCarrier           `json:"timeTrustRoot"`
}

type Result struct {
	Standard                        string   `json:"standard"`
	Route                           string   `json:"route"`
	ReleaseID                       string   `json:"release_id"`
	AuthorizationReportSHA256       string   `json:"authorization_report_sha256"`
	RecoveredAuthorizationSHA256    string   `json:"recovered_authorization_sha256"`
	TimeTrustRootSPKISHA256         string   `json:"time_trust_root_spki_sha256"`
	TimestampAuthorityID            string   `json:"timestamp_authority_id"`
	TimestampAuthoritySPKISHA256    string   `json:"timestamp_authority_spki_sha256"`
	TimePolicyEnvelopeSHA256        string   `json:"time_policy_envelope_sha256"`
	NotBeforeUnix                   int64    `json:"not_before_unix"`
	NotAfterUnix                    int64    `json:"not_after_unix"`
	AcceptedObservationIDs          []string `json:"accepted_observation_ids"`
	LastAcceptedTimestampUnix       int64    `json:"last_accepted_timestamp_unix"`
	NotYetValidResult               string   `json:"not_yet_valid_result"`
	ValidWindowResult               string   `json:"valid_window_result"`
	ClockRollbackResult             string   `json:"clock_rollback_result"`
	ExpiryResult                    string   `json:"expiry_result"`
	TrustedTimestampAuthorityResult string   `json:"trusted_timestamp_authority_result"`
	TrustedEffectiveTimeResult      string   `json:"trusted_effective_time_result"`
	Accepted                        bool     `json:"accepted"`
	Boundary                        string   `json:"boundary"`
}
