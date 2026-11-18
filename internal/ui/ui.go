// Package ui embeds and serves tikray's single-page Web UI from compiled
// assets in internal/ui/dist. It makes no external network requests and sets
// strict browser security headers on every response.
package ui

import (
	"bytes"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// ContentSecurityPolicy forbids all third-party origins, inline scripts,
// plugins, and framing while permitting same-origin assets and inline styles
// used for dynamic layout and latency bars.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

// Handler returns an http.Handler that serves the embedded Web UI and falls
// back to index.html for client-side SPA routes.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("ui: embedded dist directory missing: " + err.Error())
	}
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("ui: embedded index.html missing: " + err.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setUIHeaders(w.Header())
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cleaned := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(cleaned, "/")
		if name != "" && name != "index.html" {
			if data, err := fs.ReadFile(sub, name); err == nil {
				if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				if strings.HasPrefix(cleaned, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-store")
				}
				w.WriteHeader(http.StatusOK)
				if r.Method == http.MethodGet {
					_, _ = w.Write(data)
				}
				return
			}
			// Missing assets or explicit file paths return 404 instead of SPA HTML.
			if strings.HasPrefix(cleaned, "/assets/") || strings.Contains(path.Base(cleaned), ".") {
				w.Header().Set("Cache-Control", "no-store")
				http.NotFound(w, r)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = bytes.NewReader(indexHTML).WriteTo(w)
		}
	})
}

func setUIHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
}
