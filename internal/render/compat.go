package render

import (
	"fmt"

	"github.com/Arman2122/tikray/internal/xrayver"
)

// Feature is something the rendered config uses that xray-core has only
// from some release on.
type Feature struct {
	// Name says what the feature is, such as "TUN inbound".
	Name string
	// Min is the first xray-core release that has it.
	Min xrayver.Version
}

// Features lists what the rendered config needs from xray-core. Check
// refuses a core that is older than any of them.
var Features = []Feature{{"TUN inbound", xrayver.MinTUN}}

// Check returns an error naming the newest feature, by its Min, that
// xray-core v is too old for, or nil if v has every feature.
func Check(v xrayver.Version) error {
	var missing *Feature
	for i := range Features {
		f := &Features[i]
		if v.Less(f.Min) && (missing == nil || missing.Min.Less(f.Min)) {
			missing = f
		}
	}
	if missing == nil {
		return nil
	}
	return fmt.Errorf("render: xray-core %s is too old: the %s needs %s or newer", v, missing.Name, missing.Min)
}

// Tested is the oldest and the newest xray-core release the rendered config
// is tested against (spec §4.9, §8.2).
var Tested = [2]xrayver.Version{{Major: 26, Minor: 1, Patch: 18}, {Major: 26, Minor: 10, Patch: 21}}

// IsTested reports whether v lies within Tested, both ends included. The UI
// labels any other release "untested"; Check still decides whether it can
// run the config at all.
func IsTested(v xrayver.Version) bool {
	return !v.Less(Tested[0]) && !Tested[1].Less(v)
}
