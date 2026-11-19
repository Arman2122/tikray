package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/backup"
	"github.com/Arman2122/tikray/internal/service"
)

type serverPinger interface {
	PingServer(ctx context.Context, id string) (service.PingResult, error)
	PingAllServers(ctx context.Context) []service.PingResult
}

type coreReleaseLister interface {
	CoreReleases(ctx context.Context) service.CoreReleasesInfo
}

// NewHandlerWithUI serves the API and, when ui is non-nil, serves the embedded
// Web UI for browser GET/HEAD requests outside /v1/* and /healthz.
//
// Canonical path cleaning ensures path-traversal or duplicate-slash variants
// targeting /v1/* or /healthz always route to the authenticated API guard and
// never fall through to the UI handler.
func NewHandlerWithUI(b Backend, root string, a *auth.Store, lim *auth.Limiter, installationID string, ui http.Handler) http.Handler {
	apiHandler := NewHandler(b, root, a, lim, installationID)
	if ui == nil {
		return apiHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleaned := path.Clean("/" + r.URL.Path)
		if cleaned == "/healthz" || cleaned == "/v1" || strings.HasPrefix(cleaned, "/v1/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apiHandler.ServeHTTP(w, r)
			return
		}
		ui.ServeHTTP(w, r)
	})
}

func (h *handler) stats(w http.ResponseWriter, r *http.Request) {
	st := h.b.Stats(r.Context())
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, st)
}

func (h *handler) makeStaticLease(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if !h.decode(w, r, &in) {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(in.Address))
	if err != nil || !addr.Is4() {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, "address must be an IPv4 address")
		return
	}
	lease, err := h.b.MakeStaticLease(r.Context(), addr)
	if err != nil {
		h.fail(w, err)
		return
	}
	st, rev := h.b.State()
	redact := service.RedactorFor(st)
	v, ok := h.visibleLease(lease, redact, callerOf(r).session)
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, codeUnavailable, "router returned an invalid DHCP lease")
		return
	}
	h.reply(w, http.StatusOK, rev, v)
}

func (h *handler) requireAdminOrRoot(w http.ResponseWriter, r *http.Request, action string) bool {
	if callerOf(r).who == byToken {
		h.forbid(w, "a named API token may not "+action)
		return false
	}
	return true
}

func (h *handler) exportBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminOrRoot(w, r, "export an encrypted backup") {
		return
	}
	var in struct {
		Passphrase string `json:"passphrase"`
	}
	if !h.decode(w, r, &in) {
		return
	}
	bundle, err := h.b.ExportBackup(r.Context(), in.Passphrase)
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, bundle)
}

func (h *handler) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminOrRoot(w, r, "restore a backup") {
		return
	}
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var in struct {
		Passphrase string        `json:"passphrase"`
		Bundle     backup.Bundle `json:"bundle"`
	}
	if !h.decode(w, r, &in) {
		return
	}
	next, err := h.b.RestoreBackup(r.Context(), rev, in.Bundle, in.Passphrase)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.reply(w, http.StatusOK, next, struct {
		Revision uint64 `json:"revision"`
	}{next})
}

func (h *handler) uploadCoreInbox(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminOrRoot(w, r, "upload offline release artifacts") {
		return
	}
	name := r.PathValue("name")
	h.uploadInbox(w, r, "core", "", "", name)
}

func (h *handler) uploadGeoInbox(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminOrRoot(w, r, "upload offline release artifacts") {
		return
	}
	h.uploadInbox(w, r, "geo", r.PathValue("profile"), r.PathValue("version"), r.PathValue("name"))
}

func (h *handler) uploadInbox(w http.ResponseWriter, r *http.Request, kind, profile, version, name string) {
	n, err := h.b.UploadInbox(r.Context(), kind, profile, version, name, r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			h.writeError(w, http.StatusRequestEntityTooLarge, codeBadRequest, "uploaded file exceeds maximum size")
			return
		}
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, struct {
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
	}{name, n})
}

func (h *handler) pingServer(w http.ResponseWriter, r *http.Request) {
	p, ok := h.b.(serverPinger)
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, codeUnavailable, "latency testing is not supported")
		return
	}
	res, err := p.PingServer(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, res)
}

func (h *handler) pingAllServers(w http.ResponseWriter, r *http.Request) {
	p, ok := h.b.(serverPinger)
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, codeUnavailable, "latency testing is not supported")
		return
	}
	res := p.PingAllServers(r.Context())
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, res)
}

func (h *handler) coreReleases(w http.ResponseWriter, r *http.Request) {
	l, ok := h.b.(coreReleaseLister)
	if !ok {
		_, rev := h.b.State()
		h.reply(w, http.StatusOK, rev, service.CoreReleasesInfo{Releases: []service.CoreRelease{}})
		return
	}
	info := l.CoreReleases(r.Context())
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, info)
}
