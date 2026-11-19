package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	// Use /tags instead of /releases: 15 tags are ~7 KiB versus ~2 MiB for full
	// release asset lists, keeping router RAM and bandwidth tiny. xrayver.Parse
	// accepts only strict stable YY.M.D tags and drops prereleases automatically.
	xrayReleasesAPIURL = "https://api.github.com/repos/XTLS/Xray-core/tags?per_page=15"
	releasesCacheTTL   = 15 * time.Minute
	releasesTimeout    = 5 * time.Second
)

// CoreRelease describes one selectable xray-core version in the UI dropdown.
type CoreRelease struct {
	Version   string `json:"version"`
	Tested    bool   `json:"tested"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
}

// CoreReleasesInfo is returned by GET /v1/core/releases so the Web UI can
// populate a live version dropdown (with offline fallback to tested + installed
// releases when GitHub cannot be reached).
type CoreReleasesInfo struct {
	Latest   string        `json:"latest,omitempty"`
	Releases []CoreRelease `json:"releases"`
	Online   bool          `json:"online"`
}

var fallbackCoreVersions = []string{
	"26.11.9",
	"26.10.31",
	"26.9.30",
	"26.4.13",
	"26.3.27",
	"26.1.18",
}

// CoreReleases returns recent compatible xray-core releases (newest first),
// cached in memory for 15 minutes and merged with installed slots and tested
// fallback versions so the dropdown stays populated even on air-gapped routers.
func (s *Service) CoreReleases(ctx context.Context) CoreReleasesInfo {
	installed := map[string]bool{}
	if slots, err := artifacts.ListCores(filepath.Join(s.data, "cores")); err == nil {
		for _, sl := range slots {
			installed[sl.Version.String()] = true
		}
	}
	active := ""
	if s.runner != nil {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if rs, err := s.runner.Status(rctx); err == nil && rs.Active != nil {
			active = rs.Active.Core
		}
		cancel()
	}

	tags, online := s.cachedUpstreamReleases(ctx)

	seen := map[string]xrayver.Version{}
	add := func(raw string) {
		v, err := xrayver.Parse(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
		if err != nil || render.Check(v) != nil {
			return
		}
		seen[v.String()] = v
	}

	for _, t := range tags {
		add(t)
	}
	for v := range installed {
		add(v)
	}
	if active != "" {
		add(active)
	}
	add(render.Tested[0].String())
	add(render.Tested[1].String())
	if !online {
		for _, fb := range fallbackCoreVersions {
			add(fb)
		}
	}

	versions := make([]xrayver.Version, 0, len(seen))
	for _, v := range seen {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[j].Less(versions[i])
	})

	out := CoreReleasesInfo{
		Releases: make([]CoreRelease, 0, len(versions)),
		Online:   online,
	}
	for _, v := range versions {
		vs := v.String()
		out.Releases = append(out.Releases, CoreRelease{
			Version:   vs,
			Tested:    render.IsTested(v),
			Installed: installed[vs],
			Active:    active != "" && active == vs,
		})
	}
	if len(out.Releases) > 0 {
		out.Latest = out.Releases[0].Version
	}
	return out
}

func (s *Service) cachedUpstreamReleases(ctx context.Context) ([]string, bool) {
	now := s.now()
	s.mu.Lock()
	if s.releaseCacheAt.Add(releasesCacheTTL).After(now) && len(s.releaseCache) > 0 {
		tags := append([]string(nil), s.releaseCache...)
		s.mu.Unlock()
		return tags, true
	}
	s.mu.Unlock()

	tags, err := s.fetchGitHubReleases(ctx)
	if err != nil || len(tags) == 0 {
		return nil, false
	}
	s.mu.Lock()
	s.releaseCache = append([]string(nil), tags...)
	s.releaseCacheAt = now
	s.mu.Unlock()
	return tags, true
}

func (s *Service) fetchGitHubReleases(ctx context.Context) ([]string, error) {
	if tags, err := fetchReleaseTagsWithClient(ctx, &http.Client{Timeout: releasesTimeout}); err == nil && len(tags) > 0 {
		return tags, nil
	}
	if s.socks == "" || s.repairBridge {
		return nil, context.DeadlineExceeded
	}
	d, err := proxy.SOCKS5("tcp", s.socks, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, context.DeadlineExceeded
	}
	tr := &http.Transport{DialContext: cd.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	return fetchReleaseTagsWithClient(ctx, &http.Client{Transport: tr, Timeout: releasesTimeout})
}

func fetchReleaseTagsWithClient(ctx context.Context, hc *http.Client) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, releasesTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, xrayReleasesAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "tikray")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, context.DeadlineExceeded
	}
	var payload []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&payload); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(payload))
	for _, r := range payload {
		if r.Name != "" {
			tags = append(tags, r.Name)
		}
	}
	return tags, nil
}
