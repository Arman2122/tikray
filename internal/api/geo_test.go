package api

import (
	"bytes"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
)

func TestGeoAPIUsesAuthenticatedService(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, token := e.token(t, "geo-test")
	for _, op := range []struct {
		path, body, method string
		args               []any
	}{
		{"/v1/geo/update", `{"profile":"iran","version":"latest"}`, "GeoUpdate", []any{"iran", "latest"}},
		{"/v1/geo/rollback", "", "GeoRollback", nil},
	} {
		t.Run(op.method, func(t *testing.T) {
			before := len(e.f.recorded())
			for _, tc := range []struct {
				h    http.Header
				code int
			}{{nil, 401}, {cookieOnly(sess), 403}, {withCSRF(sess), 200}, {bearer(token), 200}} {
				r := e.do(t, http.MethodPost, op.path, op.body, tc.h)
				if r.status != tc.code {
					t.Fatalf("status %d, expected %d", r.status, tc.code)
				}
				if tc.code == 200 {
					before++
					calls := e.f.recorded()
					if len(calls) != before || calls[before-1].Method != op.method || !reflect.DeepEqual(calls[before-1].Args, op.args) || !bytes.Contains(r.body, []byte(`"outcome":"committed"`)) {
						t.Fatal("operation did not dispatch exactly once and return its outcome")
					}
				} else if len(e.f.recorded()) != before {
					t.Fatal("unauthorized call reached geo service")
				}
			}
		})
	}

	const hidden = "private-fixture-marker"
	for _, body := range []string{
		`{"profile":"https://` + hidden + `","version":"latest"}`,
		`{"profile":"iran","version":"../` + hidden + `"}`,
		`{"profile":"iran","version":""}`,
		`{"profile":"custom","version":"latest","checksum":"` + hidden + `"}`,
	} {
		before := len(e.f.recorded())
		r := e.do(t, http.MethodPost, "/v1/geo/update", body, bearer(token))
		if r.status != http.StatusBadRequest || len(e.f.recorded()) != before || bytes.Contains(r.body, []byte(hidden)) {
			t.Fatal("invalid geo update reached the service or exposed request data")
		}
	}
}

func TestGeoPendingReportsFixedServiceError(t *testing.T) {
	e := newAuthEnv(t, true)
	const private = "private-fixture-value"
	e.f.err = errors.Join(artifacts.ErrGeoPending, errors.New(private))
	e.f.result = artifacts.Result{Outcome: artifacts.OutcomeRefused}
	r := e.do(t, http.MethodPost, "/v1/geo/rollback", "", bearer(testToken))
	if r.status != 503 || !bytes.Contains(r.body, []byte(`"error":"geo_pending"`)) || bytes.Contains(r.body, []byte(private)) {
		t.Fatal("pending geo state returned a misleading or private response")
	}
}
