package api

import (
	"net/http"

	"github.com/Arman2122/tikray/internal/artifacts"
)

func (h *handler) geoUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Profile string `json:"profile"`
		Version string `json:"version"`
	}
	if !h.decode(w, r, &in) {
		return
	}
	if !artifacts.ValidGeoTarget(in.Profile, in.Version) {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, "invalid geo profile or release")
		return
	}
	ctx, done := detached(r)
	defer done()
	res, err := h.b.GeoUpdate(ctx, in.Profile, in.Version)
	h.outcome(w, res, err)
}

func (h *handler) geoRollback(w http.ResponseWriter, r *http.Request) {
	ctx, done := detached(r)
	defer done()
	res, err := h.b.GeoRollback(ctx)
	h.outcome(w, res, err)
}
