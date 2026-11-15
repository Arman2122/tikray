package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const geoTestSite = "\x0a\x0e\x0a\x02IR\x12\x08\x08\x02\x12\x04a.ir"
const geoTestIP = "\x0a\x0e\x0a\x02IR\x12\x08\x0a\x04\xc0\x00\x02\x00\x10\x18"

func geoTestFiles(version string) map[string]string {
	payloads := map[string]string{"geoip.dat": geoTestIP, "geosite.dat": geoTestSite, "domestic-v4.txt": "192.0.2.0/24\n"}
	meta := geoMeta{Version: version, Site: []string{"geosite:ir"}, IP: []string{"geoip:ir"}, SHA256: map[string]string{}}
	for file, s := range payloads {
		h := sha256.Sum256([]byte(s))
		meta.SHA256[file] = hex.EncodeToString(h[:])
	}
	b, _ := json.Marshal(meta)
	payloads["meta.json"] = string(b)
	return payloads
}

func TestGeoPublisherFallbackAndImmutableStaging(t *testing.T) {
	files := geoTestFiles("r1")
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/publisher/latest":
			fmt.Fprint(w, "r1\n")
		case "/publisher/r1/meta.json", "/publisher/r1/geosite.dat", "/publisher/r1/domestic-v4.txt", "/mirror/r1/geoip.dat":
			fmt.Fprint(w, files[filepath.Base(r.URL.Path)])
		case "/publisher/r1/geoip.dat":
			fmt.Fprint(w, "private-fixture-value")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	data := t.TempDir()
	u := CoreUpdater{Data: data, GeoSource: GeoSourceConfig{CustomURL: server.URL + "/publisher", Direct: server.Client(), Mirrors: []string{server.URL + "/mirror/{version}/{file}"}}}
	slot, err := u.StageGeo(t.Context(), "custom", "latest")
	if err != nil {
		t.Fatal(err)
	}
	g, ps, err := LoadGeo(data, slot)
	if err != nil || !slices.Equal(ps, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) || !slices.Equal(g.Site, []string{"geosite:ir"}) {
		t.Fatal("verified fallback did not yield intended slot")
	}
	if !slices.Contains(requests, "/mirror/r1/geoip.dat") || slices.Contains(requests, "/mirror/r1/meta.json") {
		t.Fatal("mirror provided verification or did not provide payload")
	}
	profile, err := GeoSlotProfile(data, slot)
	if profile != "custom" || err != nil {
		t.Fatal("no valid profile for active slot")
	}
	original, _ := os.Stat(filepath.Join(data, "geo", slot))
	repeated, err := u.StageGeo(t.Context(), "custom", "r1")
	if err != nil || repeated != slot {
		t.Fatal("could not reuse immutable slot", err)
	}
	now, _ := os.Stat(filepath.Join(data, "geo", slot))
	if !os.SameFile(original, now) {
		t.Fatal("replaced existing slot")
	}
	if err := os.WriteFile(filepath.Join(data, "geo", slot, "geoip.dat"), []byte("bad"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := u.StageGeo(t.Context(), "custom", "r1"); err == nil {
		t.Fatal("accepted or overwrote a corrupt immutable slot")
	}
	if _, err := SameGeo(data, slot, slot); err == nil {
		t.Fatal("equal names hid corrupt content")
	}
}

func TestGeoInboxNeedsIndependentPublisherProof(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			data := t.TempDir()
			files := geoTestFiles("r1")
			for name, body := range files {
				dir := filepath.Join(data, "inbox", "geo", "custom", "r1")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if trusted {
				dir := filepath.Join(data, "state", "geo-trust", "custom", "r1")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(files["meta.json"]), 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewTLSServer(http.NotFoundHandler())
			defer server.Close()
			u := CoreUpdater{Data: data, GeoSource: GeoSourceConfig{CustomURL: server.URL + "/private-fixture-value", Direct: server.Client()}}
			slot, err := u.StageGeo(t.Context(), "custom", "r1")
			if trusted {
				if err != nil || slot == "" {
					t.Fatal("trusted inbox refused", err)
				}
			} else if err == nil || slot != "" || strings.Contains(err.Error(), "private-fixture-value") {
				t.Fatal("untrusted inbox accepted or error disclosed source")
			}
		})
	}
}

type geoTransportFunc func(*http.Request) (*http.Response, error)

func (f geoTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGeoBuiltinsUseVerifiedCountryData(t *testing.T) {
	for _, profile := range []string{"iran", "loyalsoldier", "v2fly"} {
		t.Run(profile, func(t *testing.T) {
			ip, site := geoTestIP, geoTestSite
			if profile != "iran" {
				ip = strings.Replace(ip, "IR", "CN", 1)
				site = strings.Replace(site, "IR", "CN", 1)
			}
			if profile == "iran" {
				site = strings.Replace(site, "\x0e\x0a\x02IR", "\x17\x0a\x0bCATEGORY-IR", 1)
			}
			content := map[string]string{"geoip.dat": ip, "geosite.dat": site, "dlc.dat": site}
			version := "20261023"
			if profile == "v2fly" {
				version += "+20261022"
			}
			var seen []string
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				file := filepath.Base(r.URL.Path)
				seen = append(seen, r.URL.Path)
				if strings.HasSuffix(file, ".sha256sum") {
					name := strings.TrimSuffix(file, ".sha256sum")
					publishedName := name
					if profile == "iran" {
						publishedName = "release/" + name
					}
					fmt.Fprintf(w, "%x  %s\n", sha256.Sum256([]byte(content[name])), publishedName)
					return
				}
				if body, ok := content[file]; ok {
					fmt.Fprint(w, body)
					return
				}
				http.NotFound(w, r)
			})
			client := &http.Client{Transport: geoTransportFunc(func(r *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				return rec.Result(), nil
			})}
			u := CoreUpdater{Data: t.TempDir(), GeoSource: GeoSourceConfig{Direct: client}}
			slot, err := u.StageGeo(context.Background(), profile, version)
			if err != nil {
				t.Fatal(err)
			}
			g, ps, err := LoadGeo(u.Data, slot)
			if err != nil || len(g.Site) != 1 || !slices.Equal(ps, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
				t.Fatal("builtin did not derive verified IPv4")
			}
			if profile == "v2fly" && (!slices.Contains(seen, "/v2fly/domain-list-community/releases/download/20261022/dlc.dat") || !slices.Contains(seen, "/v2fly/geoip/releases/download/20261023/geoip.dat")) {
				t.Fatal("v2fly did not use both pinned publishers")
			}
		})
	}
}

func TestGeoContentAndPrune(t *testing.T) {
	data := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		files := geoTestFiles(parts[0])
		name := parts[1]
		if parts[0] == "r3" {
			val := "192.0.2.128/25\n"
			files["domestic-v4.txt"] = val
			var m geoMeta
			_ = json.Unmarshal([]byte(files["meta.json"]), &m)
			sum := sha256.Sum256([]byte(val))
			m.SHA256["domestic-v4.txt"] = hex.EncodeToString(sum[:])
			b, _ := json.Marshal(m)
			files["meta.json"] = string(b)
		}
		v, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, v)
	}))
	defer server.Close()
	u := CoreUpdater{Data: data, GeoSource: GeoSourceConfig{CustomURL: server.URL, Direct: server.Client()}}
	versions := map[string]string{}
	for _, tag := range []string{"r1", "r2", "r3", "r4"} {
		s, e := u.StageGeo(t.Context(), "custom", tag)
		if e != nil {
			t.Fatal(e)
		}
		versions[tag] = s
	}
	for _, tc := range []struct {
		a, b string
		want bool
	}{{"r1", "r2", true}, {"r1", "r3", false}, {"", "r1", false}, {"", "", true}} {
		same, e := SameGeo(data, versions[tc.a], versions[tc.b])
		if e != nil || same != tc.want {
			t.Fatal("incorrect content equality", e)
		}
	}
	owner := filepath.Join(data, "geo", versions["r4"], "owner")
	if err := os.WriteFile(owner, []byte("owner"), 0644); err != nil {
		t.Fatal(err)
	}
	if e := PruneGeo(data, []string{versions["r2"], versions["r3"]}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(data, "geo", versions["r1"])); !os.IsNotExist(e) {
		t.Fatal("expired managed slot preserved")
	}
	if _, e := os.Stat(owner); e != nil {
		t.Fatal("owner content removed")
	}
	for _, v := range []string{"r2", "r3"} {
		if _, _, e := LoadGeo(data, versions[v]); e != nil {
			t.Fatal("active or previous slot removed")
		}
	}
}

func TestGeoRejectsMalformedPayloadBeforePublication(t *testing.T) {
	for _, bad := range []string{"checksum", "geoip.dat", "geosite.dat", "domestic-v4.txt", "missing country"} {
		t.Run(bad, func(t *testing.T) {
			data := t.TempDir()
			files := geoTestFiles("r1")
			var m geoMeta
			_ = json.Unmarshal([]byte(files["meta.json"]), &m)
			switch bad {
			case "checksum":
				m.SHA256["geosite.dat"] = strings.Repeat("0", 64)
			case "missing country":
				m.IP = []string{"geoip:absent"}
			default:
				files[bad] += "\xff"
				h := sha256.Sum256([]byte(files[bad]))
				m.SHA256[bad] = hex.EncodeToString(h[:])
			}
			meta, _ := json.Marshal(m)
			files["meta.json"] = string(meta)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, ok := files[filepath.Base(r.URL.Path)]
				if !ok {
					http.NotFound(w, r)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			u := CoreUpdater{Data: data, GeoSource: GeoSourceConfig{CustomURL: server.URL, Direct: server.Client()}}
			if slot, e := u.StageGeo(t.Context(), "custom", "r1"); e == nil || slot != "" {
				t.Fatal("malformed bundle accepted")
			}
			entries, e := os.ReadDir(filepath.Join(data, "geo"))
			if e != nil || len(entries) != 0 {
				t.Fatal("failed stage left data in slot root")
			}
		})
	}
}

func TestGeoCrashCleanupRequiresOriginalDirectory(t *testing.T) {
	for _, tc := range []string{"stage", "retire", "replaced", "foreign child", "foreign scratch"} {
		t.Run(tc, func(t *testing.T) {
			data := t.TempDir()
			fd, e := openGeoDir(data, true, "geo")
			if e != nil {
				t.Fatal(e)
			}
			defer syscall.Close(fd)
			root := filepath.Join(data, "geo")
			temp := filepath.Join(root, ".tmp-geo-private-test")
			if e := os.Mkdir(temp, 0700); e != nil {
				t.Fatal(e)
			}
			child := filepath.Join(temp, "geoip.dat.part")
			if e := os.WriteFile(child, []byte("old data"), 0600); e != nil {
				t.Fatal(e)
			}
			if tc != "foreign scratch" {
				dest := filepath.Base(temp)
				if tc == "retire" {
					dest = ".old-geo-private-test"
				}
				sub, e := os.Open(temp)
				if e != nil {
					t.Fatal(e)
				}
				e = recordGeoWork(fd, int(sub.Fd()), dest)
				sub.Close()
				if e != nil {
					t.Fatal(e)
				}
				if tc == "retire" {
					if e := os.Rename(temp, filepath.Join(root, dest)); e != nil {
						t.Fatal(e)
					}
					temp = filepath.Join(root, dest)
				}
			}
			if tc == "replaced" {
				if e := os.Rename(temp, temp+"-saved"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(temp, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if tc == "foreign child" {
				if e := os.WriteFile(filepath.Join(temp, "owner.cfg"), []byte("keep"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			e = PruneGeo(data, nil)
			switch tc {
			case "retire", "stage":
				if e != nil {
					t.Fatal(e)
				}
				if _, e := os.Lstat(temp); !os.IsNotExist(e) {
					t.Fatal("orphaned owned geo payload")
				}
			case "replaced", "foreign child":
				if e == nil {
					t.Fatal("accepted replaced or mixed-use scratch directory")
				}
				if _, e := os.Stat(temp); e != nil {
					t.Fatal("removed unverified directory")
				}
			default:
				if e != nil {
					t.Fatal(e)
				}
				if _, e := os.Stat(child); e != nil {
					t.Fatal("removed unrecorded lookalike")
				}
			}
		})
	}
}

func TestGeoPayloadsReadableThroughRunnerMount(t *testing.T) {
	// A service may deliberately use a private umask for the state volume.
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	files := geoTestFiles("r1")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, s)
	}))
	defer server.Close()
	u := CoreUpdater{Data: t.TempDir(), GeoSource: GeoSourceConfig{CustomURL: server.URL, Direct: server.Client()}}
	slot, e := u.StageGeo(t.Context(), "custom", "r1")
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		st, e := os.Stat(filepath.Join(u.Data, "geo", slot, name))
		if e != nil || st.Mode().Perm() != 0644 {
			t.Fatal("verified payload is not readable by a separate runner user")
		}
	}
}

func TestGeoRedirectDoesNotDisclosePublisherRequest(t *testing.T) {
	const private = "private-fixture-only"
	var calls int
	c := geoClient(&http.Client{Transport: geoTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://cdn.example/asset"}}, Body: http.NoBody, Request: r}, nil
		}
		if r.Referer() != "" {
			t.Error("a redirect disclosed the previous publisher URL")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})})
	resp, err := c.Get("https://publisher.example/asset?key=" + private)
	if err != nil || calls != 2 {
		t.Fatal("approved HTTPS redirect not exercised")
	}
	resp.Body.Close()
}
