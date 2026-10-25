// Package compat checks render's golden configs against real xray-core
// releases: each internal/render/testdata/<scenario>.xray.json must pass
// `xray run -test` on the oldest release tikray supports and on the newest
// two (spec §8.2).
//
// Its tests carry the "compat" build tag. They build the releases (see
// lab.XrayBinaryVersion), so they need git, the Go module proxy and some
// minutes the first time, and root: releases before 26.10 open the config's
// TUN device during the test. Run them with
//
//	go test -tags compat -count=1 -timeout 60m ./test/compat/...
//
// TIKRAY_COMPAT_VERSIONS, a comma-separated list of lab versions (vYY.M.D
// release tags or v1.YYMMDD.0 module versions), replaces the releases. As
// non-root the tests skip, unless TIKRAY_COMPAT_REQUIRED=1 makes that a
// failure.
package compat
