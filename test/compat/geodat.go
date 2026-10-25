//go:build compat

package compat

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// domainType is the Domain.Type that matches a domain and its subdomains.
const domainType = 2

// writeGeoDat writes geosite.dat and geoip.dat into dir, the files xray-core
// loads geosite:<code> and geoip:<code> matchers from. sites maps each
// geosite code to its domains, each of which matches itself and its
// subdomains; ips maps each geoip code to its CIDR prefixes. The files hold
// those codes and nothing else: enough for xray to load the codes a config
// names, not real geo data.
//
// They are a protobuf GeoSiteList and GeoIPList, as xray-core defines them
// (app/router/config.proto up to 26.3, common/geodata/geodat.proto in 26.10;
// the wire format is the same). Each code is written in upper case, as xray
// looks it up, and first in its entry, where xray's reader expects it.
func writeGeoDat(dir string, sites, ips map[string][]string) error {
	var siteList []byte
	for _, code := range slices.Sorted(maps.Keys(sites)) {
		if code == "" {
			return errors.New("geosite: empty code")
		}
		site := appendString(nil, 1, strings.ToUpper(code)) // code
		for _, d := range sites[code] {
			var domain []byte
			domain = protowire.AppendTag(domain, 1, protowire.VarintType) // type
			domain = protowire.AppendVarint(domain, domainType)
			domain = appendString(domain, 2, d) // value
			site = appendBytes(site, 2, domain) // domain
		}
		siteList = appendBytes(siteList, 1, site) // entry
	}
	var ipList []byte
	for _, code := range slices.Sorted(maps.Keys(ips)) {
		if code == "" {
			return errors.New("geoip: empty code")
		}
		geoip := appendString(nil, 1, strings.ToUpper(code)) // code
		for _, s := range ips[code] {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("geoip:%s: %w", code, err)
			}
			cidr := appendBytes(nil, 1, p.Masked().Addr().AsSlice())  // ip
			cidr = protowire.AppendTag(cidr, 2, protowire.VarintType) // prefix
			cidr = protowire.AppendVarint(cidr, uint64(p.Bits()))
			geoip = appendBytes(geoip, 2, cidr) // cidr
		}
		ipList = appendBytes(ipList, 1, geoip) // entry
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), siteList, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "geoip.dat"), ipList, 0o644)
}

// appendBytes appends field num holding v, a bytes or message field.
func appendBytes(b []byte, num protowire.Number, v []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, num, protowire.BytesType), v)
}

// appendString appends field num holding the string v.
func appendString(b []byte, num protowire.Number, v string) []byte {
	return protowire.AppendString(protowire.AppendTag(b, num, protowire.BytesType), v)
}
