package artifacts

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

var errGeoData = errors.New("artifacts: invalid geo data or missing domestic code")

// The public GeoIPList/GeoSiteList wire formats are an outer repeated entry
// (field 1); each entry names a country code and holds repeated CIDR or Domain
// submessages. Read one entry at a time under the same cap as the download.
func walkGeoData(ctx context.Context, file string, visit func(string, bool, []byte) error) error {
	f, e := os.Open(file)
	if e != nil {
		return errGeoData
	}
	defer f.Close()
	r := bufio.NewReader(f)
	entries := 0
	var buf []byte
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		tag, e := binary.ReadUvarint(r)
		if e == io.EOF {
			break
		}
		if e != nil || tag != 10 {
			return errGeoData
		}
		length, e := binary.ReadUvarint(r)
		if e != nil || length == 0 || length > maxGeoAsset {
			return errGeoData
		}
		if int(length) > cap(buf) {
			buf = make([]byte, int(length))
		}
		entry := buf[:int(length)]
		if _, e = io.ReadFull(r, entry); e != nil {
			return errGeoData
		}
		var code string
		reverse := false
		for rest := entry; len(rest) > 0; {
			n, typ, b := protowire.ConsumeTag(rest)
			if b < 0 {
				return errGeoData
			}
			rest = rest[b:]
			switch n {
			case 1:
				value, k := protowire.ConsumeBytes(rest)
				if typ != protowire.BytesType || k < 0 || len(value) == 0 || len(value) > 256 || !utf8.Valid(value) || code != "" {
					return errGeoData
				}
				code = strings.ToUpper(string(value))
				rest = rest[k:]
			case 3:
				v, k := protowire.ConsumeVarint(rest)
				if typ != protowire.VarintType || k < 0 || v > 1 {
					return errGeoData
				}
				reverse = v == 1
				rest = rest[k:]
			default:
				k := protowire.ConsumeFieldValue(n, typ, rest)
				if k < 0 {
					return errGeoData
				}
				rest = rest[k:]
			}
		}
		if code == "" {
			return errGeoData
		}
		if e := visit(code, reverse, entry); e != nil {
			return e
		}
		entries++
	}
	if entries == 0 {
		return errGeoData
	}
	return nil
}

func geoRecords(ctx context.Context, entry []byte, record func([]byte) error) error {
	for len(entry) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, typ, k := protowire.ConsumeTag(entry)
		if k < 0 {
			return errGeoData
		}
		entry = entry[k:]
		if n == 2 {
			sub, k := protowire.ConsumeBytes(entry)
			if k < 0 || typ != protowire.BytesType {
				return errGeoData
			}
			if e := record(sub); e != nil {
				return e
			}
			entry = entry[k:]
		} else {
			k := protowire.ConsumeFieldValue(n, typ, entry)
			if k < 0 {
				return errGeoData
			}
			entry = entry[k:]
		}
	}
	return nil
}

func geoCIDR(b []byte) (netip.Prefix, error) {
	var address netip.Addr
	var bits uint64
	var seenBits bool
	for len(b) > 0 {
		num, typ, k := protowire.ConsumeTag(b)
		if k < 0 {
			return netip.Prefix{}, errGeoData
		}
		b = b[k:]
		switch num {
		case 1:
			raw, k := protowire.ConsumeBytes(b)
			if k < 0 || typ != protowire.BytesType || address.IsValid() {
				return netip.Prefix{}, errGeoData
			}
			addr, ok := netip.AddrFromSlice(raw)
			if !ok {
				return netip.Prefix{}, errGeoData
			}
			address = addr
			b = b[k:]
		case 2:
			v, k := protowire.ConsumeVarint(b)
			if k < 0 || typ != protowire.VarintType || v > 128 || seenBits {
				return netip.Prefix{}, errGeoData
			}
			bits = v
			seenBits = true
			b = b[k:]
		default:
			k := protowire.ConsumeFieldValue(num, typ, b)
			if k < 0 {
				return netip.Prefix{}, errGeoData
			}
			b = b[k:]
		}
	}
	if !address.IsValid() || bits > uint64(address.BitLen()) {
		return netip.Prefix{}, errGeoData
	}
	return netip.PrefixFrom(address, int(bits)).Masked(), nil
}

// Domain and its optional attributes must be complete wire messages; xray
// itself checks the candidate's domain semantics during its runtime trial.
func geoDomain(b []byte) error {
	validValue := false
	for len(b) > 0 {
		num, typ, k := protowire.ConsumeTag(b)
		if k < 0 {
			return errGeoData
		}
		b = b[k:]
		switch num {
		case 1:
			v, k := protowire.ConsumeVarint(b)
			if typ != protowire.VarintType || k < 0 || v > 3 {
				return errGeoData
			}
			b = b[k:]
		case 2, 3:
			v, k := protowire.ConsumeBytes(b)
			if k < 0 || typ != protowire.BytesType {
				return errGeoData
			}
			b = b[k:]
			if num == 2 {
				if validValue || len(v) == 0 || !utf8.Valid(v) {
					return errGeoData
				}
				validValue = true
				continue
			}
			for len(v) > 0 {
				_, _, n := protowire.ConsumeField(v)
				if n < 0 {
					return errGeoData
				}
				v = v[n:]
			}
		default:
			k := protowire.ConsumeFieldValue(num, typ, b)
			if k < 0 {
				return errGeoData
			}
			b = b[k:]
		}
	}
	if !validValue {
		return errGeoData
	}
	return nil
}

func checkGeoAssets(ctx context.Context, dir string, m geoMeta) error {
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		required := map[string]bool{}
		var inspect func([]byte) error
		if name == "geoip.dat" {
			for _, matcher := range m.IP {
				required[strings.ToUpper(strings.TrimLeft(strings.TrimPrefix(matcher, "geoip:"), "!"))] = true
			}
			inspect = func(b []byte) error { _, e := geoCIDR(b); return e }
		} else {
			for _, matcher := range m.Site {
				code, _, _ := strings.Cut(strings.TrimPrefix(matcher, "geosite:"), "@")
				required[strings.ToUpper(code)] = true
			}
			inspect = geoDomain
		}
		seen := map[string]bool{}
		err := walkGeoData(ctx, filepath.Join(dir, name), func(code string, _ bool, entry []byte) error {
			if seen[code] {
				return errGeoData
			}
			seen[code] = true
			delete(required, code)
			return geoRecords(ctx, entry, inspect)
		})
		if err != nil {
			return err
		}
		if len(required) != 0 {
			return errGeoData
		}
	}
	return nil
}

func geoIPRanges(ctx context.Context, file, country string) ([]netip.Prefix, error) {
	var ps []netip.Prefix
	found := false
	err := walkGeoData(ctx, file, func(code string, reverse bool, entry []byte) error {
		if code != country {
			return nil
		}
		if found || reverse {
			return errGeoData
		}
		found = true
		return geoRecords(ctx, entry, func(b []byte) error {
			p, e := geoCIDR(b)
			if e != nil {
				return e
			}
			if p.Addr().Is4() {
				if len(ps) >= maxGeoPrefixes {
					return errGeoData
				}
				ps = append(ps, p)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if !found || len(ps) == 0 {
		return nil, errGeoData
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if x := a.Addr().Compare(b.Addr()); x != 0 {
			return x
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	return slices.Compact(ps), nil
}
