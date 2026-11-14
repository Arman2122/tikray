// Package routerosfiles contains the reviewed RouterOS release script sources.
package routerosfiles

import "embed"

// Sources is embedded at build time so packaging cannot pick up scripts
// supplied beside an image or downloaded during installation.
//
//go:embed *.rsc
var Sources embed.FS
