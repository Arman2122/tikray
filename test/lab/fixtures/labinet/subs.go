package labinet

import (
	"fmt"
	"net/http"
	"strings"
)

// subPrefix is where HTTPHandler serves subscriptions.
const subPrefix = "/sub/"

// CheckSubName returns an error, naming the rule, when name is not one that
// /sub/<name> serves: a subscription written under such a name would be a 404.
func CheckSubName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("labinet serves only subscription names that match %s (a letter, digit or underscore, then up to 127 letters, digits, dots, underscores, pluses or hyphens), not %q", nameRE, name)
	}
	return nil
}

// serveSub answers GET /sub/<name> with the file <name> of dir, as text/plain,
// the way a subscription provider answers with its list of share links. The
// file is read on every request, so a test switches what a subscription says
// by rewriting it while labinet runs, and a file that is not there (yet, or any
// more) is a 404, like every name that is not a plain file name of dir. An
// empty dir serves nothing.
func serveSub(w http.ResponseWriter, r *http.Request, dir string) {
	if !readOnly(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, subPrefix)
	if dir == "" || !nameRE.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	// A subscription changes between two fetches; a proxy or a client in
	// between must not answer from before.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	serveFile(w, r, dir, name)
}
