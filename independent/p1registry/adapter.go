package p1registry

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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	SourceA15Commit        = "461412075d97d9b8a8202e89fc3a9da3b6743f1b"
	SourceA15ReportSHA256  = "89a4fcda3b0ad8a90803b58a53c2eba485a5f8afbfe99d7c370c5b6ab248403c"
	SourceA15CapsuleSHA256 = "f954f2fbdab0f20f18ad4d3c03a5cd23156b40e0c5c6f21bcbb2aeb776de7785"
	SourceReleaseID        = int64(363652216)
	SourceReleaseTag       = "eigiib-p1-a15-live-fixture-v2"
	RegistryHost           = "ghcr.io"
	RegistryRepository     = "nico59000/eigiib-norm-p1-a16"
	RegistryTag            = "p1-a16-fixture-v1"
	ManifestDigest         = "sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8"
	ManifestSize           = 1493
	ManifestMediaType      = "application/vnd.oci.image.manifest.v1+json"
	ArtifactType           = "application/vnd.eigiib.cross-registry-release-set.v1"
	ConfigDigest           = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	Boundary               = "named-ghcr-oci-publication-cross-registry-digest-readback-closure"
)

type LayerExpectation struct {
	Name       string
	MediaType  string
	Size       int
	Digest     string
	SourcePath string
}

var ExpectedLayers = []LayerExpectation{
	{
		Name:       "eigiib-p1-a14-fixed-1.1.archive.txt",
		MediaType:  "application/vnd.eigiib.fixed-release.archive.v1+text",
		Size:       190,
		Digest:     "sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682",
		SourcePath: "tests/fixtures/p1-a14/fixed-release-archive.txt",
	},
	{
		Name:       "eigiib-p1-a14-fixed-1.1.descriptor.json",
		MediaType:  "application/vnd.eigiib.fixed-release.descriptor.v1+json",
		Size:       776,
		Digest:     "sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1",
		SourcePath: "tests/fixtures/p1-a14/fixed-release-descriptor.json",
	},
	{
		Name:       "eigiib-p1-a15-live-release-manifest.json",
		MediaType:  "application/vnd.eigiib.github-release-manifest.v1+json",
		Size:       1421,
		Digest:     "sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b",
		SourcePath: "tests/fixtures/p1-a15/live-release-manifest.json",
	},
}

type SourceAsset struct {
	APIDigest                   string `json:"apiDigest"`
	AssetID                     int64  `json:"assetId"`
	AuthenticatedDownloadSHA256 string `json:"authenticatedDownloadSha256"`
	Name                        string `json:"name"`
	PublicDownloadSHA256        string `json:"publicDownloadSha256"`
	SHA256                      string `json:"sha256"`
	Size                        int    `json:"size"`
}

type SourceEvidence struct {
	Assets     []SourceAsset `json:"assets"`
	Commit     string        `json:"commit"`
	ReleaseID  int64         `json:"releaseId"`
	ReleaseTag string        `json:"releaseTag"`
	Repository string        `json:"repository"`
}

type ConfigDescriptor struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
}

type RegistryLayerEvidence struct {
	AuthenticatedRegistryContentDigest *string `json:"authenticatedRegistryContentDigest"`
	AuthenticatedRegistrySHA256        string  `json:"authenticatedRegistrySha256"`
	Digest                             string  `json:"digest"`
	GitHubReleaseSHA256                string  `json:"githubReleaseSha256"`
	MediaType                          string  `json:"mediaType"`
	Name                               string  `json:"name"`
	PublicRegistryContentDigest        *string `json:"publicRegistryContentDigest"`
	PublicRegistrySHA256               string  `json:"publicRegistrySha256"`
	Size                               int     `json:"size"`
}

type RegistryEvidence struct {
	ArtifactType      string                  `json:"artifactType"`
	Config            ConfigDescriptor        `json:"config"`
	Host              string                  `json:"host"`
	Layers            []RegistryLayerEvidence `json:"layers"`
	ManifestDigest    string                  `json:"manifestDigest"`
	ManifestMediaType string                  `json:"manifestMediaType"`
	ManifestSize      int                     `json:"manifestSize"`
	PublicTagListing  []string                `json:"publicTagListing"`
	Repository        string                  `json:"repository"`
	Tag               string                  `json:"tag"`
}

type Decisions struct {
	AuthenticatedRegistryReadback      string `json:"authenticatedRegistryReadback"`
	CrossRegistryDigestIdentity        string `json:"crossRegistryDigestIdentity"`
	DurableRetention                   string `json:"durableRetention"`
	ExternalRegistryPublication        string `json:"externalRegistryPublication"`
	ProductionAuthorization            string `json:"productionAuthorization"`
	PublicRegistryReadback             string `json:"publicRegistryReadback"`
	RegistryAdministrativeImmutability string `json:"registryAdministrativeImmutability"`
	TagToManifestBinding               string `json:"tagToManifestBinding"`
	UniversalInteroperability          string `json:"universalInteroperability"`
}

type Evidence struct {
	Boundary   string           `json:"boundary"`
	CapturedAt string           `json:"capturedAt"`
	Decisions  Decisions        `json:"decisions"`
	Registry   RegistryEvidence `json:"registry"`
	Source     SourceEvidence   `json:"source"`
	Standard   string           `json:"standard"`
}

type ManifestDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type OCIManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	ArtifactType  string               `json:"artifactType"`
	Config        ManifestDescriptor   `json:"config"`
	Layers        []ManifestDescriptor `json:"layers"`
	Annotations   map[string]string    `json:"annotations"`
}

type Capsule struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Standard  string `json:"standard"`
}

type CapsulePayload struct {
	Boundary                 string `json:"boundary"`
	EvidenceSHA256           string `json:"evidenceSha256"`
	OCIManifestSHA256        string `json:"ociManifestSha256"`
	Registry                 string `json:"registry"`
	RegistryTag              string `json:"registryTag"`
	Sequence                 int    `json:"sequence"`
	SourceP1A15CapsuleSHA256 string `json:"sourceP1A15CapsuleSha256"`
	SourceP1A15Commit        string `json:"sourceP1A15Commit"`
	SourceP1A15ReportSHA256  string `json:"sourceP1A15ReportSha256"`
	SourceReleaseID          int64  `json:"sourceReleaseId"`
	SourceReleaseTag         string `json:"sourceReleaseTag"`
	Standard                 string `json:"standard"`
}

type PortableLayer struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Name      string `json:"name"`
	Size      int    `json:"size"`
}

type PortableResult struct {
	ArtifactType       string           `json:"artifactType"`
	Boundary           string           `json:"boundary"`
	Config             ConfigDescriptor `json:"config"`
	Decisions          Decisions        `json:"decisions"`
	Layers             []PortableLayer  `json:"layers"`
	ManifestDigest     string           `json:"manifestDigest"`
	ManifestMediaType  string           `json:"manifestMediaType"`
	ManifestSize       int              `json:"manifestSize"`
	PublicTags         []string         `json:"publicTags"`
	RegistryHost       string           `json:"registryHost"`
	RegistryRepository string           `json:"registryRepository"`
	RegistryTag        string           `json:"registryTag"`
	SourceP1A15Commit  string           `json:"sourceP1A15Commit"`
	SourceReleaseID    int64            `json:"sourceReleaseId"`
	SourceReleaseTag   string           `json:"sourceReleaseTag"`
	Standard           string           `json:"standard"`
	Route              string           `json:"route,omitempty"`
}

func require(condition bool, message string) error {
	if !condition {
		return errors.New(message)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func strictDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func expectedManifest() OCIManifest {
	layers := make([]ManifestDescriptor, 0, len(ExpectedLayers))
	for _, item := range ExpectedLayers {
		layers = append(layers, ManifestDescriptor{
			MediaType:   item.MediaType,
			Digest:      item.Digest,
			Size:        item.Size,
			Annotations: map[string]string{"org.opencontainers.image.title": item.Name},
		})
	}
	return OCIManifest{
		SchemaVersion: 2,
		MediaType:     ManifestMediaType,
		ArtifactType:  ArtifactType,
		Config: ManifestDescriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    ConfigDigest,
			Size:      2,
		},
		Layers: layers,
		Annotations: map[string]string{
			"org.opencontainers.image.source":      "https://github.com/Nico59000/EIGIIB-norm",
			"org.opencontainers.image.revision":    SourceA15Commit,
			"org.opencontainers.image.title":       "EIGIIB P1-A16 external registry fixture",
			"org.opencontainers.image.description": "Exact P1-A15 GitHub Release assets republished as a closed OCI artifact set.",
			"org.opencontainers.image.version":     RegistryTag,
		},
	}
}

func validateManifestBytes(data []byte) error {
	if err := require(len(data) == ManifestSize, "OCI manifest size mismatch"); err != nil {
		return err
	}
	if err := require("sha256:"+sha256Hex(data) == ManifestDigest, "OCI manifest digest mismatch"); err != nil {
		return err
	}
	var actual OCIManifest
	if err := strictDecode(data, &actual); err != nil {
		return err
	}
	expectedBytes, err := json.Marshal(expectedManifest())
	if err != nil {
		return err
	}
	actualBytes, err := json.Marshal(actual)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		return errors.New("OCI manifest content mismatch")
	}
	return nil
}

func expectedDecisions() Decisions {
	return Decisions{
		AuthenticatedRegistryReadback:      "conformant",
		CrossRegistryDigestIdentity:        "conformant-for-closed-three-asset-set",
		DurableRetention:                   "not-claimed",
		ExternalRegistryPublication:        "conformant-for-named-ghcr-oci-repository-scope",
		ProductionAuthorization:            "not-claimed",
		PublicRegistryReadback:             "conformant",
		RegistryAdministrativeImmutability: "not-claimed",
		TagToManifestBinding:               "conformant-at-capture-time",
		UniversalInteroperability:          "not-claimed",
	}
}

func validateSourceFiles(root string) error {
	report, err := fileSHA256(filepath.Join(root, "tests/fixtures/p1-a15/expected-report.json"))
	if err != nil {
		return err
	}
	if err := require(report == SourceA15ReportSHA256, "actual A15 report hash mismatch"); err != nil {
		return err
	}
	capsule, err := fileSHA256(filepath.Join(root, "tests/fixtures/p1-a15/capsule.json"))
	if err != nil {
		return err
	}
	if err := require(capsule == SourceA15CapsuleSHA256, "actual A15 capsule hash mismatch"); err != nil {
		return err
	}
	for _, item := range ExpectedLayers {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.SourcePath)))
		if err != nil {
			return err
		}
		if err := require(len(data) == item.Size, "source size mismatch for "+item.Name); err != nil {
			return err
		}
		if err := require("sha256:"+sha256Hex(data) == item.Digest, "source digest mismatch for "+item.Name); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidence(root string, evidence Evidence) error {
	if err := require(evidence.Standard == "EIGIIB-P1-A16", "evidence standard mismatch"); err != nil {
		return err
	}
	if err := require(evidence.CapturedAt == "2026-08-02T00:23:59Z", "capture time mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Boundary == Boundary, "evidence boundary mismatch"); err != nil {
		return err
	}
	if evidence.Decisions != expectedDecisions() {
		return errors.New("evidence decisions mismatch")
	}
	if err := require(evidence.Source.Repository == "Nico59000/EIGIIB-norm", "source repository mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Source.Commit == SourceA15Commit, "source commit mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Source.ReleaseID == SourceReleaseID, "source release id mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Source.ReleaseTag == SourceReleaseTag, "source release tag mismatch"); err != nil {
		return err
	}
	if err := require(len(evidence.Source.Assets) == 3, "source asset set mismatch"); err != nil {
		return err
	}
	expectedIDs := map[string]int64{
		"eigiib-p1-a14-fixed-1.1.archive.txt":      498366947,
		"eigiib-p1-a14-fixed-1.1.descriptor.json":  498366952,
		"eigiib-p1-a15-live-release-manifest.json": 498366956,
	}
	sourceAssets := map[string]SourceAsset{}
	for _, item := range evidence.Source.Assets {
		if _, exists := sourceAssets[item.Name]; exists {
			return errors.New("duplicate source asset")
		}
		sourceAssets[item.Name] = item
	}
	for _, expected := range ExpectedLayers {
		item, ok := sourceAssets[expected.Name]
		if !ok {
			return fmt.Errorf("missing source asset %s", expected.Name)
		}
		hexDigest := strings.TrimPrefix(expected.Digest, "sha256:")
		if err := require(item.AssetID == expectedIDs[expected.Name], "source asset id mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.Size == expected.Size, "source asset size mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.APIDigest == expected.Digest, "source API digest mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.SHA256 == hexDigest, "source digest mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.AuthenticatedDownloadSHA256 == hexDigest, "source authenticated digest mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.PublicDownloadSHA256 == hexDigest, "source public digest mismatch for "+expected.Name); err != nil {
			return err
		}
	}
	if err := require(evidence.Registry.Host == RegistryHost, "registry host mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.Repository == RegistryRepository, "registry repository mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.Tag == RegistryTag, "registry tag mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.ArtifactType == ArtifactType, "artifact type mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.ManifestMediaType == ManifestMediaType, "manifest media type mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.ManifestDigest == ManifestDigest, "manifest digest evidence mismatch"); err != nil {
		return err
	}
	if err := require(evidence.Registry.ManifestSize == ManifestSize, "manifest size evidence mismatch"); err != nil {
		return err
	}
	if evidence.Registry.Config != (ConfigDescriptor{Digest: ConfigDigest, MediaType: "application/vnd.oci.empty.v1+json", Size: 2}) {
		return errors.New("config descriptor mismatch")
	}
	if len(evidence.Registry.PublicTagListing) != 1 || evidence.Registry.PublicTagListing[0] != RegistryTag {
		return errors.New("public tag listing mismatch")
	}
	if len(evidence.Registry.Layers) != 3 {
		return errors.New("registry layer set mismatch")
	}
	registryLayers := map[string]RegistryLayerEvidence{}
	for _, item := range evidence.Registry.Layers {
		if _, exists := registryLayers[item.Name]; exists {
			return errors.New("duplicate registry layer")
		}
		registryLayers[item.Name] = item
	}
	for _, expected := range ExpectedLayers {
		item, ok := registryLayers[expected.Name]
		if !ok {
			return fmt.Errorf("missing registry layer %s", expected.Name)
		}
		hexDigest := strings.TrimPrefix(expected.Digest, "sha256:")
		if err := require(item.Digest == expected.Digest, "registry layer digest mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.MediaType == expected.MediaType, "registry layer media type mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.Size == expected.Size, "registry layer size mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.GitHubReleaseSHA256 == hexDigest, "cross-registry source mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.AuthenticatedRegistrySHA256 == hexDigest, "authenticated registry mismatch for "+expected.Name); err != nil {
			return err
		}
		if err := require(item.PublicRegistrySHA256 == hexDigest, "public registry mismatch for "+expected.Name); err != nil {
			return err
		}
		if item.AuthenticatedRegistryContentDigest != nil || item.PublicRegistryContentDigest != nil {
			return errors.New("unexpected blob digest header")
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a16/oci-manifest.json"))
	if err != nil {
		return err
	}
	if err := validateManifestBytes(manifestData); err != nil {
		return err
	}
	return validateSourceFiles(root)
}

func verifyCapsule(root string) error {
	capsuleData, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a16/capsule.json"))
	if err != nil {
		return err
	}
	var capsule Capsule
	if err := strictDecode(capsuleData, &capsule); err != nil {
		return err
	}
	if err := require(capsule.Standard == "EIGIIB-P1-A16-CAPSULE-1.0", "capsule standard mismatch"); err != nil {
		return err
	}
	if err := require(capsule.Algorithm == "Ed25519", "capsule algorithm mismatch"); err != nil {
		return err
	}
	keyData, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a16/evidence-registrar-public-key.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return errors.New("cannot decode public key PEM")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return errors.New("public key is not Ed25519")
	}
	if err := require(capsule.KeyID == "sha256:"+sha256Hex(block.Bytes), "capsule key id mismatch"); err != nil {
		return err
	}
	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(capsule.Payload)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(capsule.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payloadBytes, signature) {
		return errors.New("capsule signature invalid")
	}
	var canonicalValue any
	if err := json.Unmarshal(payloadBytes, &canonicalValue); err != nil {
		return err
	}
	canonical, err := json.Marshal(canonicalValue)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(payloadBytes, canonical) {
		return errors.New("capsule payload is not canonical JSON")
	}
	var payload CapsulePayload
	if err := strictDecode(payloadBytes, &payload); err != nil {
		return err
	}
	if err := require(payload.Standard == "EIGIIB-P1-A16-CAPSULE-PAYLOAD-1.0", "capsule payload standard mismatch"); err != nil {
		return err
	}
	if err := require(payload.Sequence == 60, "capsule sequence mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A15Commit == SourceA15Commit, "capsule source commit mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A15ReportSHA256 == SourceA15ReportSHA256, "capsule source report mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceP1A15CapsuleSHA256 == SourceA15CapsuleSHA256, "capsule source capsule mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceReleaseID == SourceReleaseID, "capsule source release id mismatch"); err != nil {
		return err
	}
	if err := require(payload.SourceReleaseTag == SourceReleaseTag, "capsule source release tag mismatch"); err != nil {
		return err
	}
	evidenceSHA, err := fileSHA256(filepath.Join(root, "tests/fixtures/p1-a16/live-registry-evidence.json"))
	if err != nil {
		return err
	}
	if err := require(payload.EvidenceSHA256 == evidenceSHA, "capsule evidence mismatch"); err != nil {
		return err
	}
	manifestSHA, err := fileSHA256(filepath.Join(root, "tests/fixtures/p1-a16/oci-manifest.json"))
	if err != nil {
		return err
	}
	if err := require(payload.OCIManifestSHA256 == manifestSHA, "capsule manifest mismatch"); err != nil {
		return err
	}
	if err := require(payload.Registry == RegistryHost+"/"+RegistryRepository, "capsule registry mismatch"); err != nil {
		return err
	}
	if err := require(payload.RegistryTag == RegistryTag, "capsule registry tag mismatch"); err != nil {
		return err
	}
	return require(payload.Boundary == Boundary, "capsule boundary mismatch")
}

func portable(evidence Evidence) PortableResult {
	layers := make([]PortableLayer, 0, len(evidence.Registry.Layers))
	for _, item := range evidence.Registry.Layers {
		layers = append(layers, PortableLayer{Name: item.Name, MediaType: item.MediaType, Size: item.Size, Digest: item.Digest})
	}
	sort.Slice(layers, func(i, j int) bool { return layers[i].Name < layers[j].Name })
	tags := append([]string(nil), evidence.Registry.PublicTagListing...)
	sort.Strings(tags)
	return PortableResult{
		Standard:           "EIGIIB-P1-A16-PORTABLE-RESULT-1.0",
		SourceP1A15Commit:  SourceA15Commit,
		SourceReleaseID:    SourceReleaseID,
		SourceReleaseTag:   SourceReleaseTag,
		RegistryHost:       RegistryHost,
		RegistryRepository: RegistryRepository,
		RegistryTag:        RegistryTag,
		ManifestMediaType:  evidence.Registry.ManifestMediaType,
		ArtifactType:       evidence.Registry.ArtifactType,
		ManifestDigest:     evidence.Registry.ManifestDigest,
		ManifestSize:       evidence.Registry.ManifestSize,
		Config:             evidence.Registry.Config,
		Layers:             layers,
		PublicTags:         tags,
		Decisions:          evidence.Decisions,
		Boundary:           evidence.Boundary,
	}
}

func ValidateFixture(root string) (PortableResult, error) {
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a16/live-registry-evidence.json"))
	if err != nil {
		return PortableResult{}, err
	}
	var evidence Evidence
	if err := strictDecode(data, &evidence); err != nil {
		return PortableResult{}, err
	}
	if err := validateEvidence(root, evidence); err != nil {
		return PortableResult{}, err
	}
	if err := verifyCapsule(root); err != nil {
		return PortableResult{}, err
	}
	return portable(evidence), nil
}

func publicToken(client *http.Client) (string, error) {
	query := url.Values{}
	query.Set("service", RegistryHost)
	query.Set("scope", "repository:"+RegistryRepository+":pull")
	req, err := http.NewRequest(http.MethodGet, "https://"+RegistryHost+"/token?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "eigiib-p1-a16-go")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token status %d", resp.StatusCode)
	}
	var value struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		return "", err
	}
	if value.Token != "" {
		return value.Token, nil
	}
	if value.AccessToken != "" {
		return value.AccessToken, nil
	}
	return "", errors.New("public token missing")
}

func registryGet(client *http.Client, token, path, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+RegistryHost+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "eigiib-p1-a16-go")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("registry GET %s status %d", path, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	return data, resp.Header.Clone(), err
}

func LivePublic(root string) (PortableResult, error) {
	expected, err := ValidateFixture(root)
	if err != nil {
		return PortableResult{}, err
	}
	client := &http.Client{Timeout: 120 * time.Second}
	token, err := publicToken(client)
	if err != nil {
		return PortableResult{}, err
	}
	base := "/v2/" + RegistryRepository
	tagManifest, tagHeaders, err := registryGet(client, token, base+"/manifests/"+RegistryTag, ManifestMediaType)
	if err != nil {
		return PortableResult{}, err
	}
	digestManifest, digestHeaders, err := registryGet(client, token, base+"/manifests/"+ManifestDigest, ManifestMediaType)
	if err != nil {
		return PortableResult{}, err
	}
	fixtureManifest, err := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a16/oci-manifest.json"))
	if err != nil {
		return PortableResult{}, err
	}
	if !bytes.Equal(tagManifest, fixtureManifest) || !bytes.Equal(digestManifest, fixtureManifest) {
		return PortableResult{}, errors.New("live manifest differs from fixture")
	}
	for _, headers := range []http.Header{tagHeaders, digestHeaders} {
		value := headers.Get("Docker-Content-Digest")
		if value != "" && value != ManifestDigest {
			return PortableResult{}, errors.New("manifest response digest mismatch")
		}
	}
	if err := validateManifestBytes(tagManifest); err != nil {
		return PortableResult{}, err
	}
	liveLayers := make([]PortableLayer, 0, len(ExpectedLayers))
	for _, item := range ExpectedLayers {
		body, headers, err := registryGet(client, token, base+"/blobs/"+item.Digest, "")
		if err != nil {
			return PortableResult{}, err
		}
		if len(body) != item.Size || "sha256:"+sha256Hex(body) != item.Digest {
			return PortableResult{}, errors.New("live blob identity mismatch for " + item.Name)
		}
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.SourcePath)))
		if err != nil {
			return PortableResult{}, err
		}
		if !bytes.Equal(body, source) {
			return PortableResult{}, errors.New("live blob differs from source for " + item.Name)
		}
		value := headers.Get("Docker-Content-Digest")
		if value != "" && value != item.Digest {
			return PortableResult{}, errors.New("blob response digest mismatch")
		}
		liveLayers = append(liveLayers, PortableLayer{Name: item.Name, MediaType: item.MediaType, Size: len(body), Digest: "sha256:" + sha256Hex(body)})
	}
	tagsBody, _, err := registryGet(client, token, base+"/tags/list", "")
	if err != nil {
		return PortableResult{}, err
	}
	var tagsValue struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := strictDecode(tagsBody, &tagsValue); err != nil {
		return PortableResult{}, err
	}
	if tagsValue.Name != RegistryRepository {
		return PortableResult{}, errors.New("registry tag listing repository mismatch")
	}
	found := false
	for _, tag := range tagsValue.Tags {
		if tag == RegistryTag {
			found = true
		}
	}
	if !found {
		return PortableResult{}, errors.New("public tag missing")
	}
	sort.Slice(liveLayers, func(i, j int) bool { return liveLayers[i].Name < liveLayers[j].Name })
	sort.Strings(tagsValue.Tags)
	expected.Route = "independent-go-stdlib"
	expected.Layers = liveLayers
	expected.PublicTags = tagsValue.Tags
	return expected, nil
}
