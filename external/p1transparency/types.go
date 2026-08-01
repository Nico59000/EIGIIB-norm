package p1transparency

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
	ID    string   `json:"id,omitempty"`
	Epoch int      `json:"epoch,omitempty"`
	Path  string   `json:"path"`
	SPKI  Identity `json:"spki"`
}

type Result struct {
	Standard                          string   `json:"standard"`
	Route                             string   `json:"route"`
	ReleaseID                         string   `json:"release_id"`
	SourceTimeReportSHA256            string   `json:"source_time_report_sha256"`
	TransparencyTrustRootSPKISHA256   string   `json:"transparency_trust_root_spki_sha256"`
	RegisteredServiceID               string   `json:"registered_service_id"`
	RegisteredServiceEpoch            int      `json:"registered_service_epoch"`
	RegisteredServiceSPKISHA256       string   `json:"registered_service_spki_sha256"`
	RecoveredServiceID                string   `json:"recovered_service_id"`
	RecoveredServiceEpoch             int      `json:"recovered_service_epoch"`
	RecoveredServiceSPKISHA256        string   `json:"recovered_service_spki_sha256"`
	WitnessThreshold                  int      `json:"witness_threshold"`
	BaselineCheckpointRoot            string   `json:"baseline_checkpoint_root"`
	CanonicalCheckpointRoot           string   `json:"canonical_checkpoint_root"`
	ConflictingCheckpointRoot         string   `json:"conflicting_checkpoint_root"`
	RecoveredCheckpointRoot           string   `json:"recovered_checkpoint_root"`
	BaselineQuorumIDs                 []string `json:"baseline_quorum_ids"`
	CanonicalQuorumIDs                []string `json:"canonical_quorum_ids"`
	ConflictingQuorumIDs              []string `json:"conflicting_quorum_ids"`
	RecoveredQuorumIDs                []string `json:"recovered_quorum_ids"`
	EquivocatingWitnessIDs            []string `json:"equivocating_witness_ids"`
	EquivocationResult                string   `json:"equivocation_result"`
	PredecessorServiceResult          string   `json:"predecessor_service_result"`
	TrustedTransparencyServiceResult  string   `json:"trusted_transparency_service_result"`
	AppendOnlyConsistencyResult       string   `json:"append_only_consistency_result"`
	GlobalAppendOnlyConsistencyResult string   `json:"global_append_only_consistency_result"`
	AcceptedCheckpointIDs             []string `json:"accepted_checkpoint_ids"`
	RejectedCheckpointIDs             []string `json:"rejected_checkpoint_ids"`
	Accepted                          bool     `json:"accepted"`
	Boundary                          string   `json:"boundary"`
}
