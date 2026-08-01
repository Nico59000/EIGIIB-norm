package p1authorization

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

type Approval struct {
	DelegateID string      `json:"delegateId"`
	Envelope   DataCarrier `json:"envelope"`
}

type Authorization struct {
	Approvals          []Approval  `json:"approvals"`
	EvaluationSequence int         `json:"evaluationSequence"`
	Payload            DataCarrier `json:"payload"`
}

type Capsule struct {
	ClaimBoundary struct {
		DoesNotImply []string `json:"doesNotImply"`
	} `json:"claimBoundary"`
	Delegates            []KeyCarrier  `json:"delegates"`
	InitialAuthorization Authorization `json:"initialAuthorization"`
	Policy               struct {
		Envelope DataCarrier `json:"envelope"`
		Payload  DataCarrier `json:"payload"`
	} `json:"policy"`
	Profile                string        `json:"profile"`
	RecoveredAuthorization Authorization `json:"recoveredAuthorization"`
	Revocation             struct {
		Envelope DataCarrier `json:"envelope"`
		Payload  DataCarrier `json:"payload"`
	} `json:"revocation"`
	SourceRelease struct {
		Identity  Identity `json:"identity"`
		Path      string   `json:"path"`
		ReleaseID string   `json:"releaseId"`
	} `json:"sourceRelease"`
	SourceReleaseSigner KeyCarrier `json:"sourceReleaseSigner"`
	StaleReplay         struct {
		EvaluationSequence        int    `json:"evaluationSequence"`
		Expected                  string `json:"expected"`
		UsesAuthorizationSequence int    `json:"usesAuthorizationSequence"`
	} `json:"staleReplay"`
	Standard  string     `json:"standard"`
	TrustRoot KeyCarrier `json:"trustRoot"`
}

type Result struct {
	Standard                      string   `json:"standard"`
	Route                         string   `json:"route"`
	ReleaseID                     string   `json:"release_id"`
	ReleaseDescriptorSHA256       string   `json:"release_descriptor_sha256"`
	ReleaseSignerSPKISHA256       string   `json:"release_signer_spki_sha256"`
	TrustRootSPKISHA256           string   `json:"trust_root_spki_sha256"`
	PolicyEnvelopeSHA256          string   `json:"policy_envelope_sha256"`
	Threshold                     int      `json:"threshold"`
	DelegateCount                 int      `json:"delegate_count"`
	InitialApprovalIDs            []string `json:"initial_approval_ids"`
	RevokedDelegateID             string   `json:"revoked_delegate_id"`
	RevocationSequence            int      `json:"revocation_sequence"`
	RecoveredApprovalIDs          []string `json:"recovered_approval_ids"`
	TrustedReleaseSignerResult    string   `json:"trusted_release_signer_result"`
	AuthorizedReleaseSignerResult string   `json:"authorized_release_signer_result"`
	Accepted                      bool     `json:"accepted"`
	Boundary                      string   `json:"boundary"`
}
