package api

import (
	"io"
	"net/http"

	"github.com/Arman2122/tikray/internal/artifacts"
)

func (h *handler) imageStatus(w http.ResponseWriter, r *http.Request) {
	component := r.PathValue("component")
	if !artifacts.ValidImageComponent(component) {
		h.writeError(w, 404, codeNotFound, "unknown image component")
		return
	}
	v, err := h.b.ImageStatus(r.Context(), component)
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, v)
}
func (h *handler) imageChange(w http.ResponseWriter, r *http.Request) {
	component := r.PathValue("component")
	if !artifacts.ValidImageComponent(component) {
		h.writeError(w, 404, codeNotFound, "unknown image component")
		return
	}
	var op artifacts.ImageOperation
	var err error
	switch r.PathValue("action") {
	case "update":
		var in struct {
			Version string `json:"version"`
		}
		if !h.decode(w, r, &in) {
			return
		}
		if !artifacts.ValidImageVersion(in.Version) {
			h.writeError(w, 400, codeBadRequest, "invalid image version")
			return
		}
		ctx, stop := detached(r)
		defer stop()
		op, err = h.b.ImageUpdate(ctx, component, in.Version)
	case "rollback":
		if b, e := io.ReadAll(io.LimitReader(r.Body, 1)); e != nil || len(b) > 0 {
			h.writeError(w, 400, codeBadRequest, "rollback takes no body")
			return
		}
		ctx, stop := detached(r)
		defer stop()
		op, err = h.b.ImageRollback(ctx, component)
	default:
		h.writeError(w, 404, codeNotFound, "unknown image operation")
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusAccepted, rev, op)
}
