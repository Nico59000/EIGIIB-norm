package p1durability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Obj struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
	Kind   string `json:"-"`
}
type Result struct {
	Standard string         `json:"standard"`
	Route    string         `json:"route"`
	Observed map[string]any `json:"observed"`
	Portable map[string]any `json:"portable"`
}

var objects = []Obj{{"eigiib-p1-a14-fixed-1.1.archive.txt", "sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682", 190, "blob"}, {"eigiib-p1-a14-fixed-1.1.descriptor.json", "sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1", 776, "blob"}, {"eigiib-p1-a15-live-release-manifest.json", "sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b", 1421, "blob"}, {"eigiib-p1-a16-oci-config.json", "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", 2, "blob"}, {"eigiib-p1-a16-oci-manifest.json", "sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8", 1493, "manifest"}}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func get(client *http.Client, u string, headers map[string]string) ([]byte, error) {
	r, _ := http.NewRequest("GET", u, nil)
	r.Header.Set("User-Agent", "eigiib-p1-a17-go/1.0")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, e := client.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return b, nil
}
func check(o Obj, b []byte) error {
	if len(b) != o.Size || "sha256:"+hash(b) != o.Digest {
		return fmt.Errorf("identity mismatch: %s", o.Name)
	}
	return nil
}
func githubHeaders() map[string]string {
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return headers
}
func Run(root string, live bool) (Result, error) {
	evb, e := os.ReadFile(filepath.Join(root, "tests/fixtures/p1-a17/live-durability-evidence.json"))
	if e != nil {
		return Result{}, e
	}
	var ev map[string]any
	if e = json.Unmarshal(evb, &ev); e != nil {
		return Result{}, e
	}
	portable := map[string]any{"standard": "EIGIIB-P1-A17-PORTABLE-RESULT-1.0", "sourceP1A16": ev["sourceP1A16"], "retentionPolicy": ev["retentionPolicy"], "primaryLocator": ev["primaryLocation"].(map[string]any)["locator"], "recoveryRepository": ev["recoveryLocation"].(map[string]any)["repository"], "recoveryReleaseId": ev["recoveryLocation"].(map[string]any)["releaseId"], "recoveryReleaseTag": ev["recoveryLocation"].(map[string]any)["tag"], "recoveryReleaseTargetCommit": ev["recoveryLocation"].(map[string]any)["tagTargetCommit"], "protectedObjects": ev["primaryLocation"].(map[string]any)["protectedObjects"], "protectedObjectSetSha256": ev["primaryLocation"].(map[string]any)["protectedObjectSetSha256"], "restoreManifestSha256": "dc51cf8a23fa731b3b7375a36e82d2fd1a530b52cb4711cc3b92d181fd20d13e", "decisions": ev["decisions"], "boundary": ev["boundary"]}
	obs := map[string]any{"live": live}
	if live {
		c := &http.Client{Timeout: 90 * time.Second}
		q := url.Values{"service": {"ghcr.io"}, "scope": {"repository:nico59000/eigiib-norm-p1-a16:pull"}}
		tb, e := get(c, "https://ghcr.io/token?"+q.Encode(), nil)
		if e != nil {
			return Result{}, e
		}
		var tv map[string]any
		json.Unmarshal(tb, &tv)
		tok, _ := tv["token"].(string)
		if tok == "" {
			tok, _ = tv["access_token"].(string)
		}
		for _, o := range objects {
			kind := "blobs/"
			accept := "application/octet-stream"
			if o.Kind == "manifest" {
				kind = "manifests/"
				accept = "application/vnd.oci.image.manifest.v1+json"
			}
			b, e := get(c, "https://ghcr.io/v2/nico59000/eigiib-norm-p1-a16/"+kind+o.Digest, map[string]string{"Authorization": "Bearer " + tok, "Accept": accept})
			if e != nil {
				return Result{}, e
			}
			if e = check(o, b); e != nil {
				return Result{}, e
			}
		}
		rb, e := get(c, "https://api.github.com/repos/Nico59000/EIGIIB-norm/releases/tags/eigiib-p1-a17-recovery-v1", githubHeaders())
		if e != nil {
			return Result{}, e
		}
		var rel struct {
			ID     int `json:"id"`
			Assets []struct {
				Name, URL string
				Size      int    `json:"size"`
				Browser   string `json:"browser_download_url"`
			} `json:"assets"`
		}
		json.Unmarshal(rb, &rel)
		assets := map[string]string{}
		for _, a := range rel.Assets {
			assets[a.Name] = a.Browser
		}
		for _, o := range objects {
			b, e := get(c, assets[o.Name], map[string]string{"Accept": "application/octet-stream"})
			if e != nil {
				return Result{}, e
			}
			if e = check(o, b); e != nil {
				return Result{}, e
			}
		}
		obs["objectCount"] = len(objects)
	}
	return Result{"EIGIIB-P1-A17-ROUTE-RESULT-1.0", "independent-go-stdlib", obs, portable}, nil
}
func Encode(r Result) ([]byte, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	return append(bytes.TrimSpace(b), '\n'), nil
}
func ObjectNames() []string {
	n := []string{}
	for _, o := range objects {
		n = append(n, o.Name)
	}
	sort.Strings(n)
	return n
}
