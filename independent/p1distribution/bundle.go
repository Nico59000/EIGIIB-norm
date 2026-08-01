package p1distribution

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	PolicyStandard  = "EIGIIB-P1-A8-POLICY-1.0"
	BundleStandard  = "EIGIIB-P1-A8-BUNDLE-1.0"
	ReleaseStandard = "EIGIIB-P1-A8-RELEASE-1.0"
	Profile         = "exact-ustar-source-distribution-v1"
)

type snapshotEntry struct {
	Path       string
	Mode       string
	Bytes      int
	SHA256     string
	GitBlobSHA string
	Data       []byte
}

type archiveEntry struct {
	Path string
	Mode int
	Data []byte
}

type Output struct {
	Manifest []byte
	Bundle   []byte
	Release  []byte
	Sums     []byte
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func asString(policy map[string]any, key string) (string, error) {
	value, ok := policy[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("policy %s must be a non-empty string", key)
	}
	return value, nil
}

func asStrings(policy map[string]any, key string) ([]string, error) {
	raw, ok := policy[key].([]any)
	if !ok {
		return nil, fmt.Errorf("policy %s must be an array", key)
	}
	result := make([]string, len(raw))
	for i, value := range raw {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("policy %s contains a non-string", key)
		}
		result[i] = text
	}
	return result, nil
}

func ensureASCIIPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("unsafe path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe path %q", path)
		}
	}
	for _, r := range path {
		if r > 0x7f {
			return fmt.Errorf("non-ASCII path %q", path)
		}
	}
	return nil
}

func validatePolicy(policy map[string]any) error {
	expected := []string{"archiveRoot", "authorityRoot", "bundleName", "checksumName", "claimBoundary", "manifestName", "profile", "releaseId", "releaseName", "requiredPlatforms", "requiredPublishers", "sourceCommit", "standard"}
	actual := make([]string, 0, len(policy))
	for key := range policy {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return errors.New("P1-A8 policy fields differ from contract")
	}
	standard, _ := asString(policy, "standard")
	profile, _ := asString(policy, "profile")
	if standard != PolicyStandard || profile != Profile {
		return errors.New("P1-A8 policy constants differ")
	}
	for _, key := range []string{"releaseId", "archiveRoot", "bundleName", "manifestName", "releaseName", "checksumName"} {
		value, err := asString(policy, key)
		if err != nil {
			return err
		}
		if err := ensureASCIIPath(value); err != nil {
			return err
		}
		if key != "archiveRoot" && strings.Contains(value, "/") {
			return fmt.Errorf("policy %s must be a basename", key)
		}
	}
	source, err := asString(policy, "sourceCommit")
	if err != nil || len(source) != 40 {
		return errors.New("source commit differs")
	}
	if _, err := hex.DecodeString(source); err != nil {
		return errors.New("source commit differs")
	}
	authority, err := asString(policy, "authorityRoot")
	if err != nil || len(authority) != 64 {
		return errors.New("authority root differs")
	}
	if _, err := hex.DecodeString(authority); err != nil {
		return errors.New("authority root differs")
	}
	publishers, err := asStrings(policy, "requiredPublishers")
	if err != nil || strings.Join(publishers, "\n") != "reference-python-stdlib\nindependent-go-stdlib" {
		return errors.New("required publishers differ")
	}
	platforms, err := asStrings(policy, "requiredPlatforms")
	if err != nil || strings.Join(platforms, "\n") != "ubuntu-24.04\nmacos-15\nwindows-2025" {
		return errors.New("required platforms differ")
	}
	boundary, ok := policy["claimBoundary"].(map[string]any)
	if !ok || len(boundary) != 1 {
		return errors.New("claim boundary differs")
	}
	if _, err := asStrings(boundary, "doesNotImply"); err != nil {
		return errors.New("claim boundary differs")
	}
	return nil
}

func run(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func snapshot(root, source string) ([]snapshotEntry, error) {
	if _, err := run(root, "cat-file", "-e", source+"^{commit}"); err != nil {
		return nil, err
	}
	raw, err := run(root, "ls-tree", "-rz", "--full-tree", source)
	if err != nil {
		return nil, err
	}
	rows := make([]snapshotEntry, 0)
	seen := map[string]bool{}
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return nil, errors.New("Git tree record differs")
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[1] != "blob" || (meta[0] != "100644" && meta[0] != "100755") {
			return nil, fmt.Errorf("unsupported Git tree record %q", string(record))
		}
		path := string(parts[1])
		if err := ensureASCIIPath(path); err != nil {
			return nil, err
		}
		if seen[path] {
			return nil, fmt.Errorf("duplicate Git path %s", path)
		}
		seen[path] = true
		data, err := run(root, "cat-file", "blob", meta[2])
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		mode := "0644"
		if meta[0] == "100755" {
			mode = "0755"
		}
		rows = append(rows, snapshotEntry{path, mode, len(data), hex.EncodeToString(sum[:]), meta[2], data})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	return rows, nil
}

func sourceTreeRoot(rows []snapshotEntry) string {
	digest := sha256.New()
	digest.Write([]byte("EIGIIB-P1-A8 source-tree-root v1\n"))
	for _, row := range rows {
		fmt.Fprintf(digest, "%s\x00%s\x00%d\x00%s\x00%s\n", row.Path, row.Mode, row.Bytes, row.SHA256, row.GitBlobSHA)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func octal(value, width int) ([]byte, error) {
	if value < 0 {
		return nil, errors.New("negative USTAR numeric field")
	}
	digits := strconv.FormatInt(int64(value), 8)
	if len(digits) > width-1 {
		return nil, errors.New("USTAR numeric overflow")
	}
	return append([]byte(strings.Repeat("0", width-1-len(digits))+digits), 0), nil
}

func splitName(path string) ([]byte, []byte, error) {
	raw := []byte(path)
	if len(raw) <= 100 {
		return raw, nil, nil
	}
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] != '/' {
			continue
		}
		prefix, name := raw[:i], raw[i+1:]
		if len(prefix) > 0 && len(prefix) <= 155 && len(name) > 0 && len(name) <= 100 {
			return name, prefix, nil
		}
	}
	return nil, nil, fmt.Errorf("path does not fit USTAR fields: %s", path)
}

func ustarHeader(path string, mode, size int) ([]byte, error) {
	name, prefix, err := splitName(path)
	if err != nil {
		return nil, err
	}
	block := make([]byte, 512)
	copy(block[0:100], name)
	for _, spec := range []struct{ start, end, value int }{{100, 108, mode}, {108, 116, 0}, {116, 124, 0}, {124, 136, size}, {136, 148, 0}} {
		field, err := octal(spec.value, spec.end-spec.start)
		if err != nil {
			return nil, err
		}
		copy(block[spec.start:spec.end], field)
	}
	copy(block[148:156], []byte("        "))
	block[156] = '0'
	copy(block[257:263], []byte{'u', 's', 't', 'a', 'r', 0})
	copy(block[263:265], []byte("00"))
	copy(block[345:500], prefix)
	checksum := 0
	for _, value := range block {
		checksum += int(value)
	}
	text := fmt.Sprintf("%06o", checksum)
	if len(text) != 6 {
		return nil, errors.New("USTAR checksum overflow")
	}
	copy(block[148:156], append([]byte(text), 0, ' '))
	return block, nil
}

func buildUSTAR(entries []archiveEntry) ([]byte, error) {
	var out bytes.Buffer
	previous := ""
	for _, entry := range entries {
		if entry.Path <= previous {
			return nil, errors.New("USTAR entries are not strictly sorted")
		}
		previous = entry.Path
		header, err := ustarHeader(entry.Path, entry.Mode, len(entry.Data))
		if err != nil {
			return nil, err
		}
		out.Write(header)
		out.Write(entry.Data)
		if remainder := len(entry.Data) % 512; remainder != 0 {
			out.Write(make([]byte, 512-remainder))
		}
	}
	out.Write(make([]byte, 1024))
	return out.Bytes(), nil
}

func Build(root string, policy map[string]any) (Output, error) {
	if err := validatePolicy(policy); err != nil {
		return Output{}, err
	}
	source, _ := asString(policy, "sourceCommit")
	authority, _ := asString(policy, "authorityRoot")
	releaseID, _ := asString(policy, "releaseId")
	archiveRoot, _ := asString(policy, "archiveRoot")
	bundleName, _ := asString(policy, "bundleName")
	manifestName, _ := asString(policy, "manifestName")
	rows, err := snapshot(root, source)
	if err != nil {
		return Output{}, err
	}
	public := make([]map[string]any, len(rows))
	for i, row := range rows {
		public[i] = map[string]any{"path": row.Path, "mode": row.Mode, "bytes": row.Bytes, "sha256": row.SHA256, "gitBlobSha1": row.GitBlobSHA}
	}
	manifestPath := archiveRoot + "/META-INF/" + manifestName
	manifest := map[string]any{
		"standard": BundleStandard, "profile": Profile, "releaseId": releaseID,
		"sourceCommit": source, "authorityRoot": authority, "archiveRoot": archiveRoot,
		"embeddedManifestPath": manifestPath, "sourcePathPrefix": archiveRoot + "/source/",
		"sourceTreeRoot": map[string]any{"algorithm": "sha256-over-path-mode-size-sha256-gitblob-v1", "digest": sourceTreeRoot(rows)},
		"ustarProfile": map[string]any{
			"format": "ustar", "pathEncoding": "ascii", "pathOrder": "bytewise-ascending",
			"uid": 0, "gid": 0, "mtime": 0, "regularMode": "0644", "executableMode": "0755",
			"directoryEntries": false, "paxHeaders": false, "trailerBlocks": 2,
		},
		"entries": public,
	}
	manifestBytes, err := canonicalJSON(manifest)
	if err != nil {
		return Output{}, err
	}
	archiveRows := []archiveEntry{{manifestPath, 0644, manifestBytes}}
	for _, row := range rows {
		mode := 0644
		if row.Mode == "0755" {
			mode = 0755
		}
		archiveRows = append(archiveRows, archiveEntry{archiveRoot + "/source/" + row.Path, mode, row.Data})
	}
	sort.Slice(archiveRows, func(i, j int) bool { return archiveRows[i].Path < archiveRows[j].Path })
	bundle, err := buildUSTAR(archiveRows)
	if err != nil {
		return Output{}, err
	}
	bundleSum := sha256.Sum256(bundle)
	manifestSum := sha256.Sum256(manifestBytes)
	publishers, _ := asStrings(policy, "requiredPublishers")
	platforms, _ := asStrings(policy, "requiredPlatforms")
	release := map[string]any{
		"standard": ReleaseStandard, "profile": Profile, "releaseId": releaseID,
		"sourceCommit": source, "authorityRoot": authority,
		"bundle": map[string]any{"name": bundleName, "bytes": len(bundle), "sha256": hex.EncodeToString(bundleSum[:])},
		"embeddedManifest": map[string]any{
			"name": manifestName, "path": manifestPath, "bytes": len(manifestBytes),
			"sha256": hex.EncodeToString(manifestSum[:]), "sourceEntryCount": len(rows),
		},
		"sourceTreeRoot": manifest["sourceTreeRoot"],
		"requiredPublishers": publishers, "requiredPlatforms": platforms,
		"claimBoundary": policy["claimBoundary"],
	}
	releaseBytes, err := canonicalJSON(release)
	if err != nil {
		return Output{}, err
	}
	sums := []byte(fmt.Sprintf("%x  %s\n%x  %s\n", bundleSum, bundleName, manifestSum, manifestName))
	return Output{manifestBytes, bundle, releaseBytes, sums}, nil
}

func LoadPolicy(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var policy map[string]any
	if err := decoder.Decode(&policy); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing JSON data")
	}
	return policy, nil
}

func WriteOutput(outDir string, policy map[string]any, output Output) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	for key, data := range map[string][]byte{
		"manifestName": output.Manifest,
		"bundleName": output.Bundle,
		"releaseName": output.Release,
		"checksumName": output.Sums,
	} {
		name, err := asString(policy, key)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func GitBlobSHA1(raw []byte) string {
	header := []byte(fmt.Sprintf("blob %d\x00", len(raw)))
	digest := sha1.Sum(append(header, raw...))
	return hex.EncodeToString(digest[:])
}
