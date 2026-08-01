package p1transparency

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
)

const (
	Route                    = "external-go-cose"
	Standard                 = "EIGIIB-P1-A12-ROUTE-1.0"
	expectedCapsuleSHA256    = "12b3ca6c0ca260b3357993d65a8b4595f6cc23d4b8b26ca67dcee94e06148046"
	expectedA11ReportSHA256  = "2a1931b186def40a370fe3ea3d6a6b40eddd5576123c09ef0a94fa33b2d2e277"
	expectedA11CapsuleSHA256 = "526d1713db54b1648504be7cd33d6d8701a8744eeed8d5a95d4c58586b57ca46"
	registrationType         = "application/vnd.eigiib.transparency-registration+json"
	checkpointType           = "application/vnd.eigiib.transparency-checkpoint+json"
	witnessType              = "application/vnd.eigiib.transparency-witness-statement+json"
	successionType           = "application/vnd.eigiib.transparency-succession+json"
	boundary                 = "registered-transparency-quorum-consistency-equivocation-recovery-closure"
)

var keySpecs = map[string]KeyCarrier{
	"root":      {Path: "tests/fixtures/p1-a12/transparency-root-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "9e504b0d24b79e0661ce2f4069725b349071bc1d5e907239318ec34ed32083af"}},
	"log1":      {ID: "eigiib-p1-a12-log-1", Epoch: 1, Path: "tests/fixtures/p1-a12/log-epoch1-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "bb3c9be7eac73af0a65d0e8589cbd138008e57d169a5dc2661dab9a855fb1098"}},
	"log2":      {ID: "eigiib-p1-a12-log-2", Epoch: 2, Path: "tests/fixtures/p1-a12/log-epoch2-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "ae79241d76e952f6fd57a2fed9d165251c9a698ff6f891e2a6012a3c9173bedc"}},
	"witness-a": {ID: "witness-a", Path: "tests/fixtures/p1-a12/witness-a-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "dce310dea919946f06a2f2fb1400df6298fba92eaa2e5b7ad247f603140c88bf"}},
	"witness-b": {ID: "witness-b", Path: "tests/fixtures/p1-a12/witness-b-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "1e1286cb5f8e4ca7ddb5283848371e5f57c909b333c6c54be674726a76fe7f54"}},
	"witness-c": {ID: "witness-c", Path: "tests/fixtures/p1-a12/witness-c-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "55666045322ee01cbc9074b39b9d87801e2ba10ddcc95e062a76c1fa50cd2371"}},
	"witness-d": {ID: "witness-d", Path: "tests/fixtures/p1-a12/witness-d-public-key.pem", SPKI: Identity{Algorithm: "sha256", Bytes: 44, Digest: "681cad162082d1fc420628d08a2b3606a727790072510b2dd82e3db44ee1acf1"}},
}

type signedParts struct {
	Payload     []byte
	Envelope    []byte
	PayloadJSON map[string]any
}

func object(value any, label string) (map[string]any, error) {
	out, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s object", label)
	}
	return out, nil
}

func array(value any, label string) ([]any, error) {
	out, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s array", label)
	}
	return out, nil
}

func stringAt(obj map[string]any, key string) (string, error) {
	value, ok := obj[key].(string)
	if !ok {
		return "", fmt.Errorf("%s string", key)
	}
	return value, nil
}

func intAt(obj map[string]any, key string) (int64, error) {
	switch value := obj[key].(type) {
	case json.Number:
		return value.Int64()
	case float64:
		return int64(value), nil
	case int:
		return int64(value), nil
	case int64:
		return value, nil
	default:
		return 0, fmt.Errorf("%s integer", key)
	}
}

func carrier(value any) ([]byte, Identity, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, Identity{}, err
	}
	var c DataCarrier
	if err = json.Unmarshal(raw, &c); err != nil {
		return nil, Identity{}, err
	}
	bytesValue, err := carrierBytes(c)
	return bytesValue, c.Identity, err
}

func signed(value any, contentType string, key ed25519.PublicKey, der []byte) (signedParts, error) {
	obj, err := object(value, "signed")
	if err != nil || len(obj) < 2 {
		return signedParts{}, errors.New("signed carrier")
	}
	payload, _, err := carrier(obj["payload"])
	if err != nil {
		return signedParts{}, err
	}
	envelope, _, err := carrier(obj["envelope"])
	if err != nil {
		return signedParts{}, err
	}
	if err = verifyCOSE(envelope, payload, contentType, key, der); err != nil {
		return signedParts{}, err
	}
	valueJSON, err := strictJSON(payload)
	if err != nil {
		return signedParts{}, err
	}
	payloadObj, err := object(valueJSON, "signed payload")
	if err != nil {
		return signedParts{}, err
	}
	return signedParts{Payload: payload, Envelope: envelope, PayloadJSON: payloadObj}, nil
}

func hashLeaf(raw []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(raw)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func balancedRoot(raws [][]byte) ([]byte, error) {
	if len(raws) == 0 || len(raws)&(len(raws)-1) != 0 {
		return nil, errors.New("power-of-two leaves")
	}
	level := make([][]byte, len(raws))
	for i, raw := range raws {
		level[i] = hashLeaf(raw)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashNode(level[i], level[i+1]))
		}
		level = next
	}
	return level[0], nil
}

func decodeHex32(value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("hex32")
	}
	return raw, nil
}

func verifyCheckpoint(parts signedParts, expectedID, serviceID string, epoch, sequence, size int64, expectedRoot []byte) error {
	id, err := stringAt(parts.PayloadJSON, "checkpointId")
	if err != nil || id != expectedID {
		return errors.New("checkpoint id")
	}
	sid, _ := stringAt(parts.PayloadJSON, "serviceId")
	e, _ := intAt(parts.PayloadJSON, "serviceEpoch")
	s, _ := intAt(parts.PayloadJSON, "checkpointSequence")
	t, _ := intAt(parts.PayloadJSON, "treeSize")
	rootText, _ := stringAt(parts.PayloadJSON, "rootHash")
	root, err := decodeHex32(rootText)
	if err != nil || sid != serviceID || e != epoch || s != sequence || t != size || !bytes.Equal(root, expectedRoot) {
		return errors.New("checkpoint semantics")
	}
	return nil
}

func witnessIDs(root string, checkpoint map[string]any, checkpointParts signedParts, expected []string, keys map[string]ed25519.PublicKey, ders map[string][]byte) ([]string, error) {
	rows, err := array(checkpoint["witnessStatements"], "witness statements")
	if err != nil || len(rows) != len(expected) {
		return nil, errors.New("witness count")
	}
	ids := make([]string, 0, len(rows))
	for i, rowValue := range rows {
		row, err := object(rowValue, "witness row")
		if err != nil {
			return nil, err
		}
		id, err := stringAt(row, "id")
		if err != nil || id != expected[i] {
			return nil, errors.New("witness id")
		}
		parts, err := signed(row, witnessType, keys[id], ders[id])
		if err != nil {
			return nil, err
		}
		payloadID, _ := stringAt(parts.PayloadJSON, "witnessId")
		cpRoot, _ := stringAt(parts.PayloadJSON, "checkpointRootHash")
		expectedRoot, _ := stringAt(checkpointParts.PayloadJSON, "rootHash")
		cpID, _ := stringAt(parts.PayloadJSON, "checkpointId")
		expectedCPID, _ := stringAt(checkpointParts.PayloadJSON, "checkpointId")
		if payloadID != id || cpRoot != expectedRoot || cpID != expectedCPID {
			return nil, errors.New("witness binding")
		}
		ids = append(ids, id)
	}
	if len(ids) < 2 {
		return nil, errors.New("witness quorum")
	}
	return ids, nil
}

func Evaluate(root, capsulePath string) (Result, error) {
	var result Result
	capsuleRaw, err := os.ReadFile(capsulePath)
	if err != nil || identity(capsuleRaw).Digest != expectedCapsuleSHA256 {
		return result, errors.New("capsule identity")
	}
	value, err := strictJSON(capsuleRaw)
	if err != nil {
		return result, err
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(canonical, capsuleRaw) {
		return result, errors.New("capsule canonical")
	}
	capsule, err := object(value, "capsule")
	if err != nil {
		return result, err
	}

	reportRaw, _, err := safeRead(root, "tests/fixtures/p1-a11/expected-report.json")
	if err != nil || identity(reportRaw).Digest != expectedA11ReportSHA256 {
		return result, errors.New("A11 report identity")
	}
	capsuleA11Raw, _, err := safeRead(root, "tests/fixtures/p1-a11/capsule.json")
	if err != nil || identity(capsuleA11Raw).Digest != expectedA11CapsuleSHA256 {
		return result, errors.New("A11 capsule identity")
	}
	var a11 map[string]any
	if err = json.Unmarshal(reportRaw, &a11); err != nil {
		return result, err
	}
	releaseID, ok := a11["release_id"].(string)
	if !ok || releaseID != "eigiib-p1-a7-authority-1.0" {
		return result, errors.New("release id")
	}

	keys := map[string]ed25519.PublicKey{}
	ders := map[string][]byte{}
	for name, spec := range keySpecs {
		key, der, _, err := readKey(root, spec, spec.ID != "")
		if err != nil {
			return result, fmt.Errorf("key %s: %w", name, err)
		}
		keys[name] = key
		ders[name] = der
	}

	registration, err := signed(capsule["registration"], registrationType, keys["root"], ders["root"])
	if err != nil {
		return result, fmt.Errorf("registration: %w", err)
	}
	succession, err := signed(capsule["succession"], successionType, keys["root"], ders["root"])
	if err != nil {
		return result, fmt.Errorf("succession: %w", err)
	}

	leavesObj, err := object(capsule["leaves"], "leaves")
	if err != nil {
		return result, err
	}
	canonicalRows, err := array(leavesObj["canonical"], "canonical leaves")
	if err != nil || len(canonicalRows) != 4 {
		return result, errors.New("canonical leaves")
	}
	canonicalLeaves := make([][]byte, 4)
	for i, row := range canonicalRows {
		canonicalLeaves[i], _, err = carrier(row)
		if err != nil {
			return result, err
		}
	}
	forkLeaf, _, err := carrier(leavesObj["fork"])
	if err != nil {
		return result, err
	}
	recoveryRows, err := array(leavesObj["recovery"], "recovery leaves")
	if err != nil || len(recoveryRows) != 4 {
		return result, errors.New("recovery leaves")
	}
	recoveryLeaves := make([][]byte, 4)
	for i, row := range recoveryRows {
		recoveryLeaves[i], _, err = carrier(row)
		if err != nil {
			return result, err
		}
	}
	root2, _ := balancedRoot(canonicalLeaves[:2])
	right2, _ := balancedRoot(canonicalLeaves[2:])
	root4 := hashNode(root2, right2)
	forkRight, _ := balancedRoot([][]byte{canonicalLeaves[2], forkLeaf})
	forkRoot := hashNode(root2, forkRight)
	recoveryRight, _ := balancedRoot(recoveryLeaves)
	root8 := hashNode(root4, recoveryRight)

	checkpointRows, err := array(capsule["checkpoints"], "checkpoints")
	if err != nil || len(checkpointRows) != 4 {
		return result, errors.New("checkpoint count")
	}
	checkpoints := make([]map[string]any, 4)
	for i, row := range checkpointRows {
		checkpoints[i], err = object(row, "checkpoint")
		if err != nil {
			return result, err
		}
	}
	cp2, err := signed(checkpoints[0], checkpointType, keys["log1"], ders["log1"])
	if err != nil || verifyCheckpoint(cp2, "epoch1-size2", "eigiib-p1-a12-log-1", 1, 10, 2, root2) != nil {
		return result, errors.New("checkpoint size2")
	}
	cp4, err := signed(checkpoints[1], checkpointType, keys["log1"], ders["log1"])
	if err != nil || verifyCheckpoint(cp4, "epoch1-size4-main", "eigiib-p1-a12-log-1", 1, 11, 4, root4) != nil {
		return result, errors.New("checkpoint size4")
	}
	cpFork, err := signed(checkpoints[2], checkpointType, keys["log1"], ders["log1"])
	if err != nil || verifyCheckpoint(cpFork, "epoch1-size4-fork", "eigiib-p1-a12-log-1", 1, 11, 4, forkRoot) != nil {
		return result, errors.New("fork checkpoint")
	}
	cp8, err := signed(checkpoints[3], checkpointType, keys["log2"], ders["log2"])
	if err != nil || verifyCheckpoint(cp8, "epoch2-size8-recovery", "eigiib-p1-a12-log-2", 2, 20, 8, root8) != nil {
		return result, errors.New("recovery checkpoint")
	}
	if !bytes.Equal(hashNode(root2, right2), root4) || !bytes.Equal(hashNode(root2, forkRight), forkRoot) || !bytes.Equal(hashNode(root4, recoveryRight), root8) {
		return result, errors.New("consistency")
	}
	if bytes.Equal(root4, forkRoot) {
		return result, errors.New("missing equivocation")
	}

	baselineIDs, err := witnessIDs(root, checkpoints[0], cp2, []string{"witness-a", "witness-b"}, keys, ders)
	if err != nil {
		return result, err
	}
	canonicalIDs, err := witnessIDs(root, checkpoints[1], cp4, []string{"witness-a", "witness-b"}, keys, ders)
	if err != nil {
		return result, err
	}
	conflictingIDs, err := witnessIDs(root, checkpoints[2], cpFork, []string{"witness-b", "witness-c"}, keys, ders)
	if err != nil {
		return result, err
	}
	recoveredIDs, err := witnessIDs(root, checkpoints[3], cp8, []string{"witness-a", "witness-d"}, keys, ders)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual([]string{"witness-b"}, intersection(canonicalIDs, conflictingIDs)) {
		return result, errors.New("equivocating witness")
	}

	quarantine, err := object(succession.PayloadJSON["quarantine"], "quarantine")
	if err != nil {
		return result, err
	}
	witnessValues, err := array(quarantine["witnessIds"], "quarantine witnesses")
	if err != nil || len(witnessValues) != 1 || witnessValues[0] != "witness-b" {
		return result, errors.New("quarantine policy")
	}
	acceptedPredecessor, err := object(succession.PayloadJSON["acceptedPredecessor"], "accepted predecessor")
	if err != nil {
		return result, err
	}
	predRoot, _ := stringAt(acceptedPredecessor, "rootHash")
	if predRoot != hex.EncodeToString(root4) {
		return result, errors.New("succession predecessor")
	}
	registrationAction, _ := stringAt(registration.PayloadJSON, "action")
	if registrationAction != "register-transparency-service" {
		return result, errors.New("registration action")
	}

	result = Result{
		Standard:                          Standard,
		Route:                             Route,
		ReleaseID:                         releaseID,
		SourceTimeReportSHA256:            expectedA11ReportSHA256,
		TransparencyTrustRootSPKISHA256:   keySpecs["root"].SPKI.Digest,
		RegisteredServiceID:               keySpecs["log1"].ID,
		RegisteredServiceEpoch:            1,
		RegisteredServiceSPKISHA256:       keySpecs["log1"].SPKI.Digest,
		RecoveredServiceID:                keySpecs["log2"].ID,
		RecoveredServiceEpoch:             2,
		RecoveredServiceSPKISHA256:        keySpecs["log2"].SPKI.Digest,
		WitnessThreshold:                  2,
		BaselineCheckpointRoot:            hex.EncodeToString(root2),
		CanonicalCheckpointRoot:           hex.EncodeToString(root4),
		ConflictingCheckpointRoot:         hex.EncodeToString(forkRoot),
		RecoveredCheckpointRoot:           hex.EncodeToString(root8),
		BaselineQuorumIDs:                 baselineIDs,
		CanonicalQuorumIDs:                canonicalIDs,
		ConflictingQuorumIDs:              conflictingIDs,
		RecoveredQuorumIDs:                recoveredIDs,
		EquivocatingWitnessIDs:            []string{"witness-b"},
		EquivocationResult:                "detected-and-quarantined",
		PredecessorServiceResult:          "quarantined-as-required",
		TrustedTransparencyServiceResult:  "conformant-for-root-registered-successor-and-quarantined-predecessor-scope",
		AppendOnlyConsistencyResult:       "conformant-for-accepted-2-to-4-to-8-history-scope",
		GlobalAppendOnlyConsistencyResult: "not-claimed",
		AcceptedCheckpointIDs:             []string{"epoch1-size2", "epoch1-size4-main", "epoch2-size8-recovery"},
		RejectedCheckpointIDs:             []string{"epoch1-size4-fork"},
		Accepted:                          true,
		Boundary:                          boundary,
	}
	return result, nil
}

func intersection(left, right []string) []string {
	seen := map[string]bool{}
	for _, value := range left {
		seen[value] = true
	}
	out := []string{}
	for _, value := range right {
		if seen[value] {
			out = append(out, value)
		}
	}
	return out
}
