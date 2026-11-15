package routeros

import (
	"context"
	"slices"
	"strings"
)

// A projected native reply counts row/column overhead towards the session's
// 8 MiB buffer. A count and ID-only index fit at this limit (under 300 bytes
// per normal RouterOS item ID); full rows are retrieved in smaller pages.
const (
	maxAddressInventory = 24576
	smallAddressReply   = 4096
	addressPageSize     = 96 // two native words per ID, below the 256-word cap
)

// Both the owned inventory and the foreign-consumer check can see thousands
// of address-list rows. Keep the original router-side filter on every read.
func (o observation) inventoryRows(menu, fields string, q []string) ([]Row, error) {
	if menu != addressListMenu {
		return o.read(menu, fields, q...)
	}
	n, err := o.count(menu, q...)
	if err != nil {
		return nil, err
	}
	if n > maxAddressInventory {
		return nil, ErrLimit
	}
	if n <= smallAddressReply {
		return o.read(menu, fields, q...)
	}
	index, err := o.read(menu, ".id", q...)
	if err != nil {
		return nil, err
	}
	if len(index) != n {
		return nil, errDrift
	}
	ids := make([]string, 0, n)
	seen := make(map[string]bool, n)
	for _, row := range index {
		id := row[".id"]
		if !nativeRowID.MatchString(id) || seen[id] {
			return nil, ErrProtocol
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if !slices.Contains(strings.Split(fields, ","), ".id") {
		fields = ".id," + fields
	}
	out := make([]Row, 0, n)
	for batch := range slices.Chunk(ids, addressPageSize) {
		page, err := o.read(menu, fields, slices.Concat(q, valuesQuery(".id", batch...))...)
		if err != nil {
			return nil, err
		}
		if len(page) != len(batch) {
			return nil, errDrift
		}
		for _, r := range page {
			id := r[".id"]
			if !seen[id] || !slices.Contains(batch, id) {
				return nil, ErrProtocol
			}
			delete(seen, id)
		}
		out = append(out, page...)
	}
	// Even if its count is unchanged, an owner could have replaced a row
	// outside the last page. Compare complete scoped ID sets, not their order.
	now, err := o.read(menu, ".id", q...)
	if err != nil {
		return nil, err
	}
	if len(now) != n {
		return nil, errDrift
	}
	for _, id := range ids {
		seen[id] = true
	}
	for _, r := range now {
		if !seen[r[".id"]] {
			return nil, errDrift
		}
		delete(seen, r[".id"])
	}
	return out, nil
}

// Reserve enough observation capacity for the peak, including stale rows
// still present while replacement guards are built. Refuse *before* saving
// new journal intent. A restore to the old selection needs the same union.
func (p *pass) checkAddressCapacity(ctx context.Context) error {
	known := map[string]bool{}
	for _, r := range p.a.Rows {
		if r.Menu == addressListMenu {
			known[r.Comment] = true
		}
	}
	growth := 0
	for _, rows := range [][]Object{p.rows, p.holds} {
		for _, r := range rows {
			if r.Menu == addressListMenu && !known[r.Comment] {
				known[r.Comment] = true
				growth++
			}
		}
	}
	if growth == 0 {
		return nil
	}
	o := observation{ctx: ctx, c: p.fence, gen: p.a.Generation}
	for _, q := range [][]string{prefixQuery("comment", "tikray:"), reservedReferenceQuery("list")} {
		count, err := o.count(addressListMenu, q...)
		if err != nil {
			return err
		}
		if count > maxAddressInventory-growth {
			return errPolicy
		}
	}
	return nil
}
