from pathlib import Path

path = Path("independent/p1liverelease/adapter.go")
source = path.read_text(encoding="utf-8")

old_struct = '''type CapsulePayload struct {
\tStandard          string `json:"standard"`
\tSequence          int    `json:"sequence"`
\tSourceP1A14Commit string `json:"sourceP1A14Commit"`
\tEvidenceSHA256    string `json:"evidenceSha256"`
\tManifestSHA256    string `json:"manifestSha256"`
\tReleaseID         int64  `json:"releaseId"`
\tReleaseTag        string `json:"releaseTag"`
\tBoundary          string `json:"boundary"`
}
'''
new_struct = '''type CapsulePayload struct {
\tStandard                   string `json:"standard"`
\tSequence                   int    `json:"sequence"`
\tSourceP1A14Commit          string `json:"sourceP1A14Commit"`
\tSourceP1A14ReportSHA256    string `json:"sourceP1A14ReportSha256"`
\tSourceP1A14CapsuleSHA256   string `json:"sourceP1A14CapsuleSha256"`
\tEvidenceSHA256             string `json:"evidenceSha256"`
\tManifestSHA256             string `json:"manifestSha256"`
\tReleaseID                  int64  `json:"releaseId"`
\tReleaseTag                 string `json:"releaseTag"`
\tBoundary                   string `json:"boundary"`
}
'''
old_canonical = '''\tcanonical, err := json.Marshal(payload)
\tif err != nil {
\t\treturn err
\t}
\tcanonical = append(canonical, '\\n')
'''
new_canonical = '''\tvar canonicalValue map[string]any
\tif err := json.Unmarshal(payloadBytes, &canonicalValue); err != nil {
\t\treturn err
\t}
\tcanonical, err := json.Marshal(canonicalValue)
\tif err != nil {
\t\treturn err
\t}
\tcanonical = append(canonical, '\\n')
'''
old_checks = '''\tif err := require(payload.SourceP1A14Commit == SourceA14Commit, "capsule source mismatch"); err != nil {
\t\treturn err
\t}
'''
new_checks = '''\tif err := require(payload.SourceP1A14Commit == SourceA14Commit, "capsule source mismatch"); err != nil {
\t\treturn err
\t}
\tif err := require(payload.SourceP1A14ReportSHA256 == SourceA14ReportSHA256, "capsule source report mismatch"); err != nil {
\t\treturn err
\t}
\tif err := require(payload.SourceP1A14CapsuleSHA256 == SourceA14CapsuleSHA256, "capsule source capsule mismatch"); err != nil {
\t\treturn err
\t}
'''

for old, new, label in (
    (old_struct, new_struct, "capsule payload type"),
    (old_canonical, new_canonical, "canonical JSON verification"),
    (old_checks, new_checks, "A14 source checks"),
):
    if source.count(old) != 1:
        raise SystemExit(f"unexpected {label} patch cardinality")
    source = source.replace(old, new, 1)

path.write_text(source, encoding="utf-8")
Path(__file__).unlink()
