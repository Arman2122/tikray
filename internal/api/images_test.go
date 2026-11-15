package api

import (
	"bytes"
	"net/http"
	"testing"
)

func TestImageRoutesRequireAuthenticatedOwner(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, token := e.token(t, "image-fixture")
	for _, component := range []string{"tikray", "runner"} {
		path := "/v1/images/" + component
		for _, method := range []string{"update", "rollback"} {
			body := ""
			if method == "update" {
				body = `{"version":"v1.2.3"}`
			}
			before := len(e.f.recorded())
			for _, tc := range []struct {
				h    http.Header
				code int
			}{{nil, 401}, {cookieOnly(sess), 403}, {withCSRF(sess), 202}, {bearer(token), 202}} {
				res := e.do(t, "POST", path+"/"+method, body, tc.h)
				if res.status != tc.code {
					t.Fatalf("image %s %s status %d, want %d", component, method, res.status, tc.code)
				}
				if tc.code == 202 {
					before++
					if !bytes.Contains(res.body, []byte(`"operation_id"`)) {
						t.Fatal("no durable operation id returned")
					}
				}
				if len(e.f.recorded()) != before {
					t.Fatal("incorrect number of authorized mutations")
				}
			}
		}
		if e.do(t, "GET", path, "", nil).status != 401 || e.do(t, "GET", path, "", bearer(token)).status != 200 {
			t.Fatal("wrong image status authorization")
		}
	}
	const private = "private-test-value"
	before := len(e.f.recorded())
	for _, tc := range []struct{ path, body string }{{"/v1/images/runner/update", `{"version":"../` + private + `"}`}, {"/v1/images/" + private + "/update", `{"version":"v1.2.3"}`}, {"/v1/images/runner/rollback", `{"previous":"` + private + `"}`}} {
		res := e.do(t, "POST", tc.path, tc.body, bearer(token))
		if res.status < 400 || bytes.Contains(res.body, []byte(private)) || len(e.f.recorded()) != before {
			t.Fatal("invalid image mutation dispatched or exposed private input")
		}
	}
}
