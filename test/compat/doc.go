// Package compat checks tikray's xray-facing code against real xray-core
// releases: the oldest release tikray supports and the newest two (spec
// §8.2). TestXrayAcceptsGolden has each
// internal/render/testdata/<scenario>.xray.json pass `xray run -test`.
// TestXrayAPIAgainstReleases runs xray with its API and an observatory, and
// has internal/xray's Client read them.
//
// Its tests carry the "compat" build tag. They build the releases (see
// lab.XrayBinaryVersion), so they need git, the Go module proxy and some
// minutes the first time. TestXrayAcceptsGolden also needs root: releases
// before 26.10 open the config's TUN device during the test.
// TestXrayAPIAgainstReleases has no TUN device in its config, listens on
// 127.0.0.1 only, and runs as any user. Run them with
//
//	go test -tags compat -count=1 -timeout 60m ./test/compat/...
//
// TIKRAY_COMPAT_VERSIONS, a comma-separated list of lab versions (vYY.M.D
// release tags or v1.YYMMDD.0 module versions), replaces the releases. As
// non-root TestXrayAcceptsGolden skips, unless TIKRAY_COMPAT_REQUIRED=1 makes
// that a failure.
package compat
