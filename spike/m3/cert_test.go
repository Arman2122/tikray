//go:build lab

package m3

import (
	"strings"
	"testing"

	ros "github.com/go-routeros/routeros/v3"
)

func schemaTrap(err error) bool {
	de, ok := err.(*ros.DeviceError)
	if !ok {
		return false
	}
	msg := strings.ToLower(de.Sentence.Map["message"])
	return strings.Contains(msg, "unknown parameter") || strings.Contains(msg, "no such command") ||
		strings.Contains(msg, "unknown command") || strings.Contains(msg, "no such argument") ||
		strings.Contains(msg, "no such parameter") || strings.Contains(msg, "unknown argument")
}

// Try each standard tagging operation on an otherwise usable signed cert.
// Never infer support from a successful command without reading the row.
func probeSignedCert(t *testing.T, r *rig) {
	const tag = "tikray:spike-cert-proof"
	lookup := func() (id, comment string, ok bool) {
		got, err := r.admin.RunContext(r.ctx, "/certificate/print", "?name=m3-cap-api", "=.proplist=.id,comment")
		if err != nil || len(got.Re) != 1 {
			return "", "", false
		}
		return got.Re[0].Map[".id"], got.Re[0].Map["comment"], true
	}
	id, _, ok := lookup()
	if !ok || id == "" {
		r.mark(t, "C.signed-cert-confirmation", "INCONCLUSIVE", "could not identify known signed certificate")
		return
	}
	refused := 0

	for _, cmd := range [][]string{{"/certificate/set", "=.id=" + id, "=comment=" + tag}, {"/certificate/comment", "=.id=" + id, "=comment=" + tag}, {"/certificate/comment", "=numbers=" + id, "=comment=" + tag}} {
		_, err := r.admin.RunArgsContext(r.ctx, cmd)
		_, v, ok := lookup()
		if ok && v == tag {
			r.mark(t, "C.signed-cert-confirmation", "PASS", "owner set and read the exact tag on the signed certificate")
			return
		}
		if schemaTrap(err) && ok {
			refused++
		}
	}
	// A property can be allowed on creation but read-only after signing.
	add := []string{"/certificate/add", "=name=m3-tag-template", "=common-name=m3-tag-template", "=key-size=prime256v1"}
	_, createErr := r.admin.RunArgsContext(r.ctx, append(append([]string(nil), add...), "=comment="+tag))
	if createErr == nil {
		_, signErr := r.chr.RunPrivate(r.ctx, "/certificate/sign m3-tag-template")
		got, readErr := r.admin.RunContext(r.ctx, "/certificate/print", "?name=m3-tag-template", "=.proplist=.id,comment")
		if signErr == nil && readErr == nil && len(got.Re) == 1 && got.Re[0].Map["comment"] == tag {
			r.mark(t, "C.signed-cert-confirmation", "PASS", "owner added a tagged template and the signed certificate retained the tag")
		} else {
			r.mark(t, "C.signed-cert-confirmation", "INCONCLUSIVE", "tagged template did not produce a verified signed tagged row")
		}
		return
	}
	created, control := r.admin.RunArgsContext(r.ctx, add)
	if refused == 3 && schemaTrap(createErr) && control == nil {
		r.mark(t, "C.signed-cert-confirmation", "FAIL", "tagged template refused, identical template without comment accepted; signed row refused set and comment")
	} else {
		r.mark(t, "C.signed-cert-confirmation", "INCONCLUSIVE", "could not confirm certificate capability against the owner control")
	}
	// Only the throwaway template just created here is eligible for this
	// permission control. Never remove the certificate serving this session.
	if control == nil && created.Done != nil && created.Done.Map["ret"] != "" {
		id := created.Done.Map["ret"]
		cmd := []string{"/certificate/remove", "=.id=" + id}
		_, err := r.api.RunArgsContext(r.ctx, cmd)
		present := func() (bool, error) {
			rows, readErr := r.admin.RunContext(r.ctx, "/certificate/print", "?.id="+id, "=.proplist=.id")
			if readErr != nil {
				return false, readErr
			}
			return len(rows.Re) > 0, nil
		}
		exists, readErr := present()
		if err == nil && readErr == nil && !exists {
			r.mark(t, "B.remove.certificate-control", "PASS", "restricted client removed its disposable untagged template by ID")
		} else if de, ok := err.(*ros.DeviceError); ok && readErr == nil && exists && strings.Contains(strings.ToLower(de.Error()), "permission") {
			_, undoErr := r.admin.RunArgsContext(r.ctx, cmd)
			exists, readErr = present()
			if undoErr == nil && readErr == nil && !exists {
				r.mark(t, "B.remove.certificate-control", "FAIL", "restricted template removal denied and identical owner control succeeded")
			} else {
				r.mark(t, "B.remove.certificate-control", "INCONCLUSIVE", "owner removal control could not be verified")
			}
		} else {
			r.mark(t, "B.remove.certificate-control", "INCONCLUSIVE", "template removal did not yield a confirmed outcome")
		}
	}
}

func TestSignedCertComment(t *testing.T) { r := newRig(t); probeSignedCert(t, r) }
