package artifacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"golang.org/x/sys/unix"
)

// GeoSourceConfig names the independently trusted custom HTTPS publisher
// and untrusted payload mirrors. A proxy is used only after a healthy probe.
type GeoSourceConfig struct {
	CustomURL     string
	Mirrors       []string
	Direct, Proxy *http.Client
	ProxyHealthy  func(context.Context) bool
}

var (
	errGeoTarget   = errors.New("artifacts: invalid geo release")
	errGeoProof    = errors.New("artifacts: publisher geo checksum unavailable or invalid")
	errGeoSource   = errors.New("artifacts: verified geo payload unavailable")
	errGeoInstall  = errors.New("artifacts: cannot publish immutable geo slot")
	errGeoConflict = errors.New("artifacts: conflicting installed geo slot")
)

func ValidGeoProfile(s string) bool {
	switch s {
	case "iran", "v2fly", "loyalsoldier", "custom":
		return true
	}
	return false
}

func geoDate(s string) bool {
	return len(s) >= 8 && len(s) <= 20 && strings.Trim(s, "0123456789") == ""
}

// ValidGeoTarget also accepts a missing profile when a caller has not yet
// resolved its local default. StageGeo requires the resolved profile.
func ValidGeoTarget(profile, version string) bool {
	if profile == "" {
		return ValidGeoTarget("custom", version) || ValidGeoTarget("v2fly", version)
	}
	if !ValidGeoProfile(profile) {
		return false
	}
	if version == "latest" {
		return true
	}
	switch profile {
	case "custom":
		return runnerapi.ValidGeoName(version)
	case "v2fly":
		ip, site, ok := strings.Cut(version, "+")
		return ok && geoDate(ip) && geoDate(site)
	default:
		return geoDate(version)
	}
}

const geoRepo = "https://github.com/"

func geoRepos(profile string) (ip, site string) {
	switch profile {
	case "iran":
		ip = geoRepo + "Chocolate4U/Iran-v2ray-rules"
	case "loyalsoldier":
		ip = geoRepo + "Loyalsoldier/v2ray-rules-dat"
	case "v2fly":
		return geoRepo + "v2fly/geoip", geoRepo + "v2fly/domain-list-community"
	}
	return ip, ip
}

type geoAsset struct{ local, file, tag, url string }

type geoRelease struct{ profile, tag, id, slot string }

func (r geoRelease) assets(custom string) []geoAsset {
	if r.profile == "custom" {
		var assets []geoAsset
		for _, name := range []string{"geoip.dat", "geosite.dat", "domestic-v4.txt"} {
			assets = append(assets, geoAsset{name, name, r.tag, geoURL(custom, r.tag, name)})
		}
		return assets
	}
	ipTag, siteTag := r.tag, r.tag
	siteFile := "geosite.dat"
	if r.profile == "v2fly" {
		ipTag, siteTag, _ = strings.Cut(r.tag, "+")
		siteFile = "dlc.dat"
	}
	ipRepo, siteRepo := geoRepos(r.profile)
	return []geoAsset{{"geoip.dat", "geoip.dat", ipTag, geoURL(ipRepo, "releases", "download", ipTag, "geoip.dat")}, {"geosite.dat", siteFile, siteTag, geoURL(siteRepo, "releases", "download", siteTag, siteFile)}}
}
func geoURL(raw string, elems ...string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return ""
	}
	return u.JoinPath(elems...).String()
}
func geoClient(h *http.Client) *http.Client {
	c := *h
	check := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.User != nil || len(via) >= 10 {
			return errGeoSource
		}
		// A publisher or release CDN may put credentials in a download
		// query. The next hop needs the asset URL, not our previous URL.
		req.Header.Del("Referer")
		if check != nil {
			return check(req, via)
		}
		return nil
	}
	return &c
}
func (c GeoSourceConfig) upstream(ctx context.Context, f func(*http.Client) error) error {
	h := c.Direct
	if h == nil {
		h = HTTPClient("", defaultTimeout)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f(geoClient(h)) == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.Proxy != nil && c.ProxyHealthy != nil && c.ProxyHealthy(ctx) && f(geoClient(c.Proxy)) == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errGeoProof
}

// Only the configured publisher, reached directly or through the healthy
// proxy, may attest tags or digests. A mirror can never fill in these.
func (c GeoSourceConfig) small(ctx context.Context, raw string) ([]byte, error) {
	if raw == "" {
		return nil, errGeoProof
	}
	var out bytes.Buffer
	err := c.upstream(ctx, func(h *http.Client) error {
		check, stop := context.WithTimeout(ctx, latestTimeout)
		defer stop()
		out.Reset()
		return get(check, h, raw, &capWriter{w: &out, left: maxGeoMeta})
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c GeoSourceConfig) latestTag(ctx context.Context, repo string) (string, error) {
	var tag string
	err := c.upstream(ctx, func(h *http.Client) error {
		probe, stop := context.WithTimeout(ctx, latestTimeout)
		defer stop()
		client := *h
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		req, _ := http.NewRequestWithContext(probe, http.MethodGet, repo+"/releases/latest", nil)
		resp, e := client.Do(req)
		if e != nil {
			return errGeoProof
		}
		defer resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return errGeoProof
		}
		loc, e := resp.Location()
		if e != nil || loc.Scheme != "https" || loc.Host != req.URL.Host || loc.User != nil || loc.RawQuery != "" || loc.Fragment != "" {
			return errGeoProof
		}
		tag = path.Base(loc.Path)
		if !geoDate(tag) || loc.Path != strings.TrimSuffix(req.URL.Path, "/latest")+"/tag/"+tag {
			return errGeoProof
		}
		return nil
	})
	return tag, err
}

func trustedGeoFile(data, profile, version, file string) ([]byte, error) {
	parts := []string{"state", "geo-trust", profile}
	if version != "" {
		parts = append(parts, version)
	}
	dir, err := openGeoDir(data, false, parts...)
	if err != nil {
		return nil, errGeoProof
	}
	defer unix.Close(dir)
	var b bytes.Buffer
	if readGeoFile(dir, file, maxGeoMeta, &b) != nil {
		return nil, errGeoProof
	}
	return b.Bytes(), nil
}
func (u *CoreUpdater) resolveGeo(ctx context.Context, profile, version string) (geoRelease, error) {
	var r geoRelease
	if !ValidGeoProfile(profile) || !ValidGeoTarget(profile, version) {
		return r, errGeoTarget
	}
	c := u.GeoSource
	if profile == "custom" && c.CustomURL != "" && geoURL(c.CustomURL) == "" {
		return r, errGeoProof
	}
	tag := version
	if version == "latest" {
		var err error
		if profile == "custom" {
			var b []byte
			b, err = c.small(ctx, geoURL(c.CustomURL, "latest"))
			tag = strings.TrimSpace(string(b))
		} else {
			ip, site := geoRepos(profile)
			tag, err = c.latestTag(ctx, ip)
			if err == nil && profile == "v2fly" {
				var v string
				v, err = c.latestTag(ctx, site)
				tag += "+" + v
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			b, e := trustedGeoFile(u.Data, profile, "", "latest")
			if e != nil {
				return r, errGeoProof
			}
			tag = strings.TrimSpace(string(b))
		}
		if tag == "latest" || !ValidGeoTarget(profile, tag) {
			return r, errGeoProof
		}
	}
	// The name exposes neither a custom query string nor a pasted private tag.
	origin := profile
	if profile == "custom" {
		origin += "\x00" + c.CustomURL
	}
	digest := sha256.Sum256([]byte(origin + "\x00" + tag))
	id := hex.EncodeToString(digest[:])
	return geoRelease{profile, tag, id, "g-" + id[:62]}, nil
}

func checksumFile(b []byte, name string) (string, error) {
	fields := strings.Fields(string(b))
	switch len(fields) {
	case 1:
	case 2:
		file := strings.TrimPrefix(fields[1], "*")
		// The Iran publisher hashes from its build root as release/<name>.
		if file != name && file != "release/"+name {
			return "", errGeoProof
		}
	default:
		return "", errGeoProof
	}
	sum := strings.ToLower(fields[0])
	if !isSHA256Hex(sum) {
		return "", errGeoProof
	}
	return sum, nil
}
func (u *CoreUpdater) geoChecksums(ctx context.Context, r geoRelease, assets []geoAsset) (geoMeta, error) {
	manifest := func(b []byte) (geoMeta, error) {
		var m geoMeta
		if json.Unmarshal(b, &m) != nil || m.Version != r.tag {
			return geoMeta{}, errGeoProof
		}
		for _, a := range assets {
			if !isSHA256Hex(m.SHA256[a.local]) {
				return geoMeta{}, errGeoProof
			}
		}
		if r.profile == "custom" {
			g := render.Geo{Site: m.Site, IP: m.IP}
			if len(m.SHA256) != 3 || g.Validate() != nil {
				return geoMeta{}, errGeoProof
			}
		}
		return m, nil
	}
	var m geoMeta
	if r.profile == "custom" {
		b, e := u.GeoSource.small(ctx, geoURL(u.GeoSource.CustomURL, r.tag, metaFile))
		if e == nil {
			return manifest(b)
		}
	} else {
		m.SHA256 = map[string]string{}
		for _, a := range assets {
			b, e := u.GeoSource.small(ctx, a.url+".sha256sum")
			if e != nil {
				break
			}
			sum, e := checksumFile(b, a.file)
			if e != nil {
				return geoMeta{}, errGeoProof
			}
			m.SHA256[a.local] = sum
		}
		if len(m.SHA256) == len(assets) {
			return m, nil
		}
	}
	if ctx.Err() != nil {
		return geoMeta{}, ctx.Err()
	}
	b, e := trustedGeoFile(u.Data, r.profile, r.tag, metaFile)
	if e != nil {
		return geoMeta{}, errGeoProof
	}
	return manifest(b)
}

type geoSource struct {
	name  string
	fetch func(context.Context, io.Writer) error
}

func (s geoSource) Name() string                                            { return s.name }
func (s geoSource) Fetch(ctx context.Context, _ Request, w io.Writer) error { return s.fetch(ctx, w) }

func (u *CoreUpdater) fetchGeo(ctx context.Context, r geoRelease, a geoAsset, dst, want string) error {
	c := u.GeoSource
	h := c.Direct
	if h == nil {
		h = HTTPClient("", defaultTimeout)
	}
	sources := []Source{geoSource{"direct", func(ctx context.Context, w io.Writer) error {
		if a.url == "" {
			return errGeoSource
		}
		return get(ctx, geoClient(h), a.url, w)
	}}}
	if c.Proxy != nil && c.ProxyHealthy != nil {
		sources = append(sources, geoSource{"proxy", func(ctx context.Context, w io.Writer) error {
			if !c.ProxyHealthy(ctx) {
				return errProxyUnavailable
			}
			return get(ctx, geoClient(c.Proxy), a.url, w)
		}})
	}
	for _, mirror := range c.Mirrors {
		if !strings.Contains(mirror, "{file}") {
			continue
		}
		arch := u.Arch
		if arch == "" {
			arch = runtime.GOARCH
		}
		location := strings.NewReplacer("{version}", a.tag, "{arch}", arch, "{file}", a.file).Replace(mirror)
		if geoURL(location) == "" {
			continue
		}
		sources = append(sources, geoSource{"mirror", func(ctx context.Context, w io.Writer) error { return get(ctx, geoClient(h), location, w) }})
	}
	limit := int64(maxGeoAsset)
	if a.local == "domestic-v4.txt" {
		limit = maxGeoRanges
	}
	sources = append(sources, geoSource{"inbox", func(ctx context.Context, w io.Writer) error {
		dir, e := openGeoDir(u.Data, false, "inbox", "geo", r.profile, r.tag)
		if e != nil {
			return errGeoSource
		}
		defer unix.Close(dir)
		return readGeoFile(dir, a.file, limit, w)
	}})
	chain := Chain{Sources: sources, MaxBytes: limit, Timeout: u.Fetch.Timeout, Stall: u.Fetch.Stall}
	_, err := chain.Fetch(ctx, Request{File: a.local}, dst, func(p string) error {
		got, e := FileSHA256(p)
		if e != nil || got != want {
			return errGeoSource
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return errGeoSource
	}
	return nil
}

// StageGeo publishes a fully verified immutable directory. Its caller holds
// the artifacts lock until the runner/router transaction and retention finish.
func (u *CoreUpdater) StageGeo(ctx context.Context, profile, version string) (string, error) {
	r, e := u.resolveGeo(ctx, profile, version)
	if e != nil {
		return "", e
	}
	fd, e := openGeoDir(u.Data, true, "geo")
	if e != nil {
		return "", e
	}
	defer unix.Close(fd)
	if e := cleanupGeoWork(fd); e != nil {
		return "", e
	}
	return u.stageGeo(ctx, r, fd)
}

func (u *CoreUpdater) stageGeo(ctx context.Context, r geoRelease, fd int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	base := geoFDPath(fd)
	final := filepath.Join(base, r.slot)
	if _, e := os.Lstat(final); e == nil {
		sub, e := unix.Openat(fd, r.slot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return "", errGeoConflict
		}
		defer unix.Close(sub)
		m, _, e := verifyGeoFD(sub, r.slot)
		if e != nil || m.ReleaseID != r.id || m.Profile != r.profile {
			return "", errGeoConflict
		}
		return r.slot, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", errGeoConflict
	}
	assets := r.assets(u.GeoSource.CustomURL)
	m, e := u.geoChecksums(ctx, r, assets)
	if e != nil {
		return "", e
	}
	m.Version, m.Profile, m.ReleaseID = r.slot, r.profile, r.id
	staged, e := os.MkdirTemp(base, ".tmp-geo-")
	if e != nil {
		return "", errGeoInstall
	}
	tmpName := filepath.Base(staged)
	stagedFD, e := unix.Openat(fd, tmpName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", errGeoInstall
	}
	defer unix.Close(stagedFD)
	if e := recordGeoWork(fd, stagedFD, tmpName); e != nil {
		os.Remove(staged)
		return "", e
	}
	// Stage relative to the open directory, even if a path changes while a
	// download is in flight.
	staged = geoFDPath(stagedFD)
	defer cleanupGeoWork(fd)
	for _, a := range assets {
		payload := filepath.Join(staged, a.local)
		if e := u.fetchGeo(ctx, r, a, payload, m.SHA256[a.local]); e != nil {
			return "", e
		}
		// The runner can have another UID. Persist its read permission even
		// when the control process creates its temporary files under umask 077.
		f, e := os.Open(payload)
		if e != nil {
			return "", errGeoInstall
		}
		if f.Chmod(0644) != nil || f.Sync() != nil {
			f.Close()
			return "", errGeoInstall
		}
		if f.Close() != nil {
			return "", errGeoInstall
		}
	}
	if r.profile != "custom" {
		country := "CN"
		site := "cn"
		if r.profile == "iran" {
			country = "IR"
			site = "category-ir"
		}
		m.Site, m.IP = []string{"geosite:" + site}, []string{"geoip:" + strings.ToLower(country)}
		ps, e := geoIPRanges(ctx, filepath.Join(staged, "geoip.dat"), country)
		if e != nil {
			return "", e
		}
		sum := sha256.New()
		e = writeSynced(filepath.Join(staged, "domestic-v4.txt"), 0644, func(w io.Writer) error {
			out := io.MultiWriter(w, sum)
			for _, p := range ps {
				if _, e := fmt.Fprintln(out, p.String()); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			return "", errGeoInstall
		}
		m.SHA256["domestic-v4.txt"] = hex.EncodeToString(sum.Sum(nil))
	}
	// Check protobuf framing and that each configured country exists. Xray's
	// real candidate trial remains authoritative for domains and attributes.
	if e := checkGeoAssets(ctx, staged, m); e != nil {
		return "", e
	}
	b, e := json.Marshal(m)
	if e != nil || writeSynced(filepath.Join(staged, metaFile), 0644, func(w io.Writer) error { _, e := w.Write(b); return e }) != nil {
		return "", errGeoInstall
	}
	if _, _, e := verifyGeoFD(stagedFD, r.slot); e != nil {
		return "", e
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if unix.Fchmod(stagedFD, 0755) != nil || unix.Fsync(stagedFD) != nil {
		return "", errGeoInstall
	}
	if e := unix.Renameat2(fd, tmpName, fd, r.slot, unix.RENAME_NOREPLACE); e != nil {
		return "", errGeoInstall
	}
	if unix.Fsync(fd) != nil {
		return "", errGeoInstall
	}
	return r.slot, nil
}

func GeoSlotProfile(data, slot string) (string, error) {
	if slot == "" {
		return "", nil
	}
	dir, e := openGeoSlot(data, slot)
	if e != nil {
		return "", e
	}
	defer unix.Close(dir)
	m, e := readGeoMeta(dir, slot)
	if e != nil {
		return "", e
	}
	if m.Profile == "" && m.ReleaseID == "" {
		return "", nil
	}
	if !managedGeo(m) {
		return "", errGeoConflict
	}
	return m.Profile, nil
}
func managedGeo(m geoMeta) bool {
	return ValidGeoProfile(m.Profile) && isSHA256Hex(m.ReleaseID) && m.Version == "g-"+m.ReleaseID[:62]
}

// SameGeo compares verified contents including the domestic matcher lists.
// Two releases with identical assets need neither a runner trial nor native writes.
func SameGeo(data, a, b string) (bool, error) {
	load := func(slot string) (geoMeta, error) {
		if slot == "" {
			return geoMeta{}, nil
		}
		m, _, e := verifiedGeo(data, slot)
		return m, e
	}
	x, e := load(a)
	if e != nil {
		return false, e
	}
	if a == b {
		return true, nil
	}
	y, e := load(b)
	if e != nil {
		return false, e
	}
	if x.Profile != y.Profile || !slices.Equal(x.Site, y.Site) || !slices.Equal(x.IP, y.IP) {
		return false, nil
	}
	for _, name := range []string{"geoip.dat", "geosite.dat", "domestic-v4.txt"} {
		if x.SHA256[name] != y.SHA256[name] {
			return false, nil
		}
	}
	return true, nil
}

// PruneGeo retires only verified, managed slots, after the transaction is
// settled. Foreign directories, links and unreadable slots remain untouched.
func PruneGeo(data string, keep []string) error {
	for _, slot := range keep {
		if slot != "" && !runnerapi.ValidGeoName(slot) {
			return errGeoTarget
		}
	}
	// Fresh installations can roll back to the no-geo selection.
	fd, e := openGeoDir(data, false, "geo")
	if e != nil {
		return e
	}
	dir := os.NewFile(uintptr(fd), "geo")
	defer dir.Close()
	if e := cleanupGeoWork(fd); e != nil {
		return e
	}
	ents, e := dir.ReadDir(-1)
	if e != nil {
		return errGeoInstall
	}
	for _, ent := range ents {
		name := ent.Name()
		if !ent.IsDir() || !strings.HasPrefix(name, "g-") || len(name) != 64 || slices.Contains(keep, name) {
			continue
		}
		sub, e := unix.Openat(fd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			return errGeoInstall
		}
		f := os.NewFile(uintptr(sub), name)
		m, _, valid := verifyGeoFD(sub, name)
		names, e := f.Readdirnames(5)
		if e != nil && e != io.EOF {
			f.Close()
			return errGeoInstall
		}
		if valid != nil || !managedGeo(m) || len(names) != 4 {
			f.Close()
			continue
		}

		// Make the old slot unselectable before unlinking any payload. A
		// surviving receipt lets the next operation finish an interrupted purge.
		trash := ".old-geo-" + rand.Text()
		e = recordGeoWork(fd, sub, trash)
		f.Close()
		if e != nil {
			return e
		}
		if unix.Renameat2(fd, name, fd, trash, unix.RENAME_NOREPLACE) != nil {
			return errGeoInstall
		}
		if unix.Fsync(fd) != nil {
			return errGeoInstall
		}
		if e := cleanupGeoWork(fd); e != nil {
			return e
		}
	}
	if unix.Fsync(fd) != nil {
		return errGeoInstall
	}
	return nil
}
