package main

import (
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/service"
)

func TestGeoScheduleEnvironment(t *testing.T) {
	for _, tc := range []struct {
		mode, window string
		valid        bool
	}{
		{"auto", "", true}, {"manual", "02:15-04:00", true}, {"notify", "23:00-02:30", true},
		{"private-invalid-mode", "", false}, {"auto", "private-invalid-time", false},
		{"", "00:00-00:00", false}, {"notify", "23:59-24:00", false}, {"auto", "2:15-03:01", false},
	} {
		cfg, err := configFromEnv(envOf(map[string]string{"TIKRAY_GEO_MODE": tc.mode, "TIKRAY_GEO_WINDOW": tc.window}))
		if tc.valid {
			want, e := service.ParseGeoSchedule(tc.mode, tc.window)
			if err != nil || e != nil || cfg.GeoSchedule != want {
				t.Fatal("configuration did not pass the schedule to the service")
			}
			continue
		}
		if err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatal("invalid schedule was accepted or repeated")
		}
	}
}
