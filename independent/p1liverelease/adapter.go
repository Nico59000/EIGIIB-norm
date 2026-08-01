package p1liverelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	SourceA14Commit        = "586784811f1139349141728c6db966f7f54459a1"
	SourceA14ReportSHA256  = "e5d42e1cac67bb2ab4d1013c6d86332139f508326cd6b34b19d164d747d9fcaa"
	SourceA14CapsuleSHA256 = "7e157a0da1d5de8c35f15bd1bb72221343aab97395ffcd35a4f08de18312b798"
	FixedArchiveSHA256     = "14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682"
	FixedDescriptorSHA256  = "762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1"
	Repository             = "Nico59000/EIGIIB-norm"
	ReleaseTag             = "eigiib-p1-a15-live-fixture-v2"
	ReleaseName            = "EIGIIB P1-A15 canonical live fixture release"
	Boundary               = "canonical-live-github-release-asset-identity-api-readback-closure"
)

type AssetEvidence struct {
	ID                          int64  `json:"id"`
	Name                        string `json:"name"`
	State                       string `json:"state"`
	ContentType                 string `json:"content_type"`
	Size                        int64  `json:"size"`
	APIDigest                   string `json:"api_digest"`
	AuthenticatedDownloadSHA256 string `json:"authenticated_download_sha256"`
	PublicDownloadSHA256        string `json:"public_download_sha256"`
	BrowserDownloadURL          string `json:"browser_download_url"`
}

type ReleaseEvidence struct {
	ID              int64  `json:"id"`
	NodeID          string `json:"node_id"`
	TagName         string `json:"tag_name"`
	Name            string `json:"name"`
	Draft           bool   `json:"draft"`
	Prerelease      bool   `json:"prerelease"`
	Immutable       *bool  `json:"immutable"`
	TargetCommitish string `json:"target_commitish"`
	TagObjectType   string `json:"tag_object_type"`
	TagObjectSHA    string `json:"tag_object_sha"`
	PeeledCommitSHA string `json:"peeled_commit_sha"`
	CreatedAt       string `json:"created_at"`
	PublishedAt     string `json:"published_at"`
	HTMLURL         string `json:"html_url"`
}

type Evidence struct {
	Standard                 string            `json:"standard"`
	Profile                  string            `json:"profile"`
	APIVersion               string            `json:"api_version"`
	Repository               string            `json:"repository"`
	SourceP1A14Commit        string            `json:"source_p1_a14_commit"`
	SourceP1A14ReportSHA256  string            `json:"source_p1_a14_report_sha256"`
	SourceP1A14CapsuleSHA256 string            `json:"source_p1_a14_capsule_sha256"`
	Release                  ReleaseEvidence   `json:"release"`
	Assets                   []AssetEvidence   `json:"assets"`
	Decisions                map[string]string `json:"decisions"`
	Boundary                 string            `json:"boundary"`
}

type ManifestAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type Manifest struct {
	Standard                     string          `json:"standard"`
	Profile                      string          `json:"profile"`
	Repository                   string          `json:"repository"`
	ReleaseID                    int64           `json:"release_id"`
	ReleaseTag                   string          `json:"release_tag"`
	ReleaseName                  string          `json:"release_name"`
	TargetCommitSHA              string          `json:"target_commit_sha"`
	SourceP1A14Commit            string          `json:"source_p1_a14_commit"`
	SourceP1A14ReportSHA256      string          `json:"source_p1_a14_report_sha256"`
	SourceP1A14CapsuleSHA256     string          `json:"source_p1_a14_capsule_sha256"`
	FixedReleaseID               string          `json:"fixed_release_id"`
	FixedReleaseVersion          string          `json:"fixed_release_version"`
	FixedReleaseArchiveSHA256    string          `json:"fixed_release_archive_sha256"`
	FixedReleaseDescriptorSHA256 string          `json:"fixed_release_descriptor_sha256"`
	Assets                       []ManifestAsset `json:"assets"`
	ClaimBoundary                []string        `json:"claim_boundary"`
}

type Capsule struct {
	Standard  string `json:"standard"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type CapsulePayload struct {
	Standard                 string `json:"standard"`
	Sequence                 int    `json:"sequence"`
	SourceP1A14Commit        string `json:"sourceP1A14Commit"`
	SourceP1A14ReportSHA256  string `json:"sourceP1A14ReportSha256"`
	SourceP1A14CapsuleSHA256 string `json:"sourceP1A14CapsuleSha256"`
	EvidenceSHA256           string `json:"evidenceSha256"`
	ManifestSHA256           string `json:"manifestSha256"`
	ReleaseID                int64  `json:"releaseId"`
	ReleaseTag               string `json:"releaseTag"`
	Boundary                 string `json:"boundary"`
}

type PortableAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type Portable struct {
	Standard          string            `json:"standard"`
	Repository        string            `json:"repository"`
	SourceP1A14Commit string            `json:"sourceP1A14Commit"`
	ReleaseID         int64             `json:"releaseId"`
	ReleaseTag        string            `json:"releaseTag"`
	ReleaseName       string            `json:"releaseName"`
	PeeledCommitSHA   string            `json:"peeledCommitSha"`
	Draft             bool              `json:"draft"`
	Prerelease        bool              `json:"prerelease"`
	Immutable         *bool             `json:"immutable"`
	Assets            []PortableAsset   `json:"assets"`
	ManifestSHA256    string            `json:"manifestSha256"`
	Decisions         map[string]string `json:"decisions"`
	Boundary          string            `json:"boundary"`
}

type Result struct {
	Route    string   `json:"route"`
	Portable Portable `json:"portable"`
}

func shaFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func strictLoad(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return errors.New("extra JSON value")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func require(ok bool, message string) error {
	if !ok {
		return errors.New(message)
	}
	return nil
}

func verifyCapsule(root string, evidenceSHA, manifestSHA string, releaseID int64) error {
	fixture := filepath.Join(root, "tests", "fixtures", "p1-a15")
	var capsule Capsule
	if err := strictLoad(filepath.Join(fixture, "capsule.json"), &capsule); err != nil {
		return err
	}
	if err := require(capsule.Standard == "EIGIIB-P1-A15-CAPSULE-1.0", "capsule standard mismatch"); err != nil {
		return err
	}
	if err := require(capsule.Algorithm == "Ed25519", "capsule algorithm mismatch"); err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(filepath.Join(fixture, "evidence-registrar-public-key.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("public key is not Ed25519")
	}
	keyHash := sha256.Sum256(block.Bytes)
	if err := require(capsule.KeyID == "sha256:"+hex.EncodeToString(keyHash[:]), "capsule key id mismatch"); err != nil {
		return err
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(capsule.Payload)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(capsule.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payloadBytes, signature) {
		return errors.New("capsule signature invalid")
	}
	var payload CapsulePayload
	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return err
	}
	var canonicalValue map[string]any
	if err := json.Unmarshal(payloadBytes, &canonicalValue); err != nil {
		return err
	}
	canonical, err := json.Marshal(canonicalValue)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, payloadBytes) {
		return errors.New("capsule payload is not canonical")
	}
	if err := require(payload.Sequence == 50, "capsule sequence mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A14Commit == SourceA14Commit, "capsule source mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A14ReportSHA256 == SourceA14ReportSHA256, "capsule source report mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A14CapsuleSHA256 == SourceA14CapsuleSHA256, "capsule source capsule mismatch"); err != nil {
		return err
	}
	if err := require(payload.EvidenceSHA256 == evidenceSHA, "capsule evidence mismatch"); err != nil {
		return err
	}
	if err := require(payload.ManifestSHA256 == manifestSHA, "capsule manifest mismatch"); err != nil {
		return err
	}
	if err := require(payload.ReleaseID == releaseID, "capsule release id mismatch"); err != nil {
		return err
	}
	if err := require(payload.ReleaseTag == ReleaseTag, "capsule release tag mismatch"); err != nil {
		return err
	}
	return require(payload.Boundary == Boundary, "capsule boundary mismatch")
}

func Validate(root string) (Portable, error) {
	fixture := filepath.Join(root, "tests", "fixtures", "p1-a15")
	a14 := filepath.Join(root, "tests", "fixtures", "p1-a14")
	var evidence Evidence
	if err := strictLoad(filepath.Join(fixture, "live-release-evidence.json"), &evidence); err != nil {
		return Portable{}, err
	}
	var manifest Manifest
	if err := strictLoad(filepath.Join(fixture, "live-release-manifest.json"), &manifest); err != nil {
		return Portable{}, err
	}
	manifestSHA, err := shaFile(filepath.Join(fixture, "live-release-manifest.json"))
	if err != nil {
		return Portable{}, err
	}
	evidenceSHA, err := shaFile(filepath.Join(fixture, "live-release-evidence.json"))
	if err != nil {
		return Portable{}, err
	}
	checks := []struct{ got, want, msg string }{
		{evidence.Standard, "EIGIIB-P1-A15-LIVE-READBACK-EVIDENCE-1.0", "evidence standard mismatch"},
		{evidence.Repository, Repository, "repository mismatch"},
		{evidence.SourceP1A14Commit, SourceA14Commit, "source commit mismatch"},
		{evidence.SourceP1A14ReportSHA256, SourceA14ReportSHA256, "source report mismatch"},
		{evidence.SourceP1A14CapsuleSHA256, SourceA14CapsuleSHA256, "source capsule mismatch"},
		{evidence.Release.TagName, ReleaseTag, "release tag mismatch"},
		{evidence.Release.Name, ReleaseName, "release name mismatch"},
		{evidence.Release.PeeledCommitSHA, SourceA14Commit, "peeled commit mismatch"},
		{evidence.Release.TagObjectSHA, SourceA14Commit, "tag object mismatch"},
		{evidence.Release.TagObjectType, "commit", "tag type mismatch"},
		{evidence.Boundary, Boundary, "boundary mismatch"},
		{manifest.TargetCommitSHA, SourceA14Commit, "manifest target mismatch"},
	}
	for _, check := range checks {
		if check.got != check.want {
			return Portable{}, errors.New(check.msg)
		}
	}
	if evidence.Release.Draft || !evidence.Release.Prerelease {
		return Portable{}, errors.New("release flags mismatch")
	}
	if manifest.ReleaseID != evidence.Release.ID || manifest.ReleaseTag != ReleaseTag || manifest.ReleaseName != ReleaseName {
		return Portable{}, errors.New("manifest release identity mismatch")
	}
	if manifest.FixedReleaseArchiveSHA256 != FixedArchiveSHA256 || manifest.FixedReleaseDescriptorSHA256 != FixedDescriptorSHA256 {
		return Portable{}, errors.New("manifest fixed identity mismatch")
	}
	if got, _ := shaFile(filepath.Join(a14, "expected-report.json")); got != SourceA14ReportSHA256 {
		return Portable{}, errors.New("actual A14 report mismatch")
	}
	if got, _ := shaFile(filepath.Join(a14, "capsule.json")); got != SourceA14CapsuleSHA256 {
		return Portable{}, errors.New("actual A14 capsule mismatch")
	}
	if got, _ := shaFile(filepath.Join(a14, "fixed-release-archive.txt")); got != FixedArchiveSHA256 {
		return Portable{}, errors.New("actual A14 archive mismatch")
	}
	if got, _ := shaFile(filepath.Join(a14, "fixed-release-descriptor.json")); got != FixedDescriptorSHA256 {
		return Portable{}, errors.New("actual A14 descriptor mismatch")
	}
	if len(evidence.Assets) != 3 {
		return Portable{}, errors.New("asset count mismatch")
	}
	expected := map[string]string{
		"eigiib-p1-a14-fixed-1.1.archive.txt":      FixedArchiveSHA256,
		"eigiib-p1-a14-fixed-1.1.descriptor.json":  FixedDescriptorSHA256,
		"eigiib-p1-a15-live-release-manifest.json": manifestSHA,
	}
	assets := make([]PortableAsset, 0, 3)
	seen := map[string]bool{}
	for _, asset := range evidence.Assets {
		want, ok := expected[asset.Name]
		if !ok {
			return Portable{}, fmt.Errorf("unexpected asset %s", asset.Name)
		}
		if seen[asset.Name] {
			return Portable{}, fmt.Errorf("duplicate asset %s", asset.Name)
		}
		seen[asset.Name] = true
		if asset.APIDigest != "sha256:"+want || asset.AuthenticatedDownloadSHA256 != want || asset.PublicDownloadSHA256 != want {
			return Portable{}, fmt.Errorf("asset digest mismatch for %s", asset.Name)
		}
		if asset.ID <= 0 || asset.Size <= 0 || asset.State != "uploaded" {
			return Portable{}, fmt.Errorf("asset metadata mismatch for %s", asset.Name)
		}
		assets = append(assets, PortableAsset{ID: asset.ID, Name: asset.Name, Size: asset.Size, Digest: asset.APIDigest})
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })
	if err := verifyCapsule(root, evidenceSHA, manifestSHA, evidence.Release.ID); err != nil {
		return Portable{}, err
	}
	if evidence.Decisions["overall_result"] != "conformant" {
		return Portable{}, errors.New("overall result mismatch")
	}
	return Portable{
		Standard: "EIGIIB-P1-A15-PORTABLE-RESULT-1.0", Repository: Repository,
		SourceP1A14Commit: SourceA14Commit, ReleaseID: evidence.Release.ID,
		ReleaseTag: ReleaseTag, ReleaseName: ReleaseName, PeeledCommitSHA: SourceA14Commit,
		Draft: false, Prerelease: true, Immutable: evidence.Release.Immutable,
		Assets: assets, ManifestSHA256: manifestSHA, Decisions: evidence.Decisions, Boundary: Boundary,
	}, nil
}

type liveRelease struct {
	ID         int64  `json:"id"`
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Immutable  *bool  `json:"immutable"`
	Assets     []struct {
		ID                 int64  `json:"id"`
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		Digest             string `json:"digest"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func ValidateLive(portable Portable) error {
	client := &http.Client{Timeout: 60 * time.Second}
	url := "https://api.github.com/repos/" + Repository + "/releases/tags/" + ReleaseTag
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "eigiib-p1-a15-independent-go")
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("release API returned %d", response.StatusCode)
	}
	var live liveRelease
	dec := json.NewDecoder(response.Body)
	if err := dec.Decode(&live); err != nil {
		return err
	}
	if live.ID != portable.ReleaseID || live.TagName != ReleaseTag || live.Name != ReleaseName || live.Draft || !live.Prerelease {
		return errors.New("live release metadata changed")
	}
	if (live.Immutable == nil) != (portable.Immutable == nil) || (live.Immutable != nil && *live.Immutable != *portable.Immutable) {
		return errors.New("live immutable field changed")
	}
	if len(live.Assets) != len(portable.Assets) {
		return errors.New("live asset count changed")
	}
	want := map[string]PortableAsset{}
	for _, asset := range portable.Assets {
		want[asset.Name] = asset
	}
	for _, asset := range live.Assets {
		expected, ok := want[asset.Name]
		if !ok {
			return fmt.Errorf("unexpected live asset %s", asset.Name)
		}
		if asset.ID != expected.ID || asset.Size != expected.Size || asset.Digest != expected.Digest {
			return fmt.Errorf("live asset metadata changed for %s", asset.Name)
		}
		download, err := client.Get(asset.BrowserDownloadURL)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(download.Body)
		download.Body.Close()
		if readErr != nil {
			return readErr
		}
		if download.StatusCode != http.StatusOK {
			return fmt.Errorf("download returned %d", download.StatusCode)
		}
		sum := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(sum[:]) != expected.Digest {
			return fmt.Errorf("public download changed for %s", asset.Name)
		}
	}
	return nil
}
