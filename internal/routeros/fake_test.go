package routeros

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The same state serves native reads, mutations and fresh generation snapshots.
type diffRouter struct {
	gen                 uint64
	serial              int
	rows                []Observed
	writes              [][]string
	lose                bool
	cutBefore, cutAfter int
	afterWrite          func()
}

func newDiffRouter() *diffRouter                                         { return &diffRouter{gen: 1} }
func (f *diffRouter) Generation() uint64                                 { return f.gen }
func (*diffRouter) Listen(context.Context, []string, func(Change)) error { return ErrRequest }
func (f *diffRouter) insert(menu, tag string, props map[string]string) string {
	f.serial++
	id := fmt.Sprintf("*%X", f.serial)
	f.rows = append(f.rows, Observed{Menu: menu, ID: id, Comment: tag, Props: props})
	return id
}
func (f *diffRouter) tag(s string) *Observed {
	for i := range f.rows {
		if f.rows[i].Comment == s {
			return &f.rows[i]
		}
	}
	return nil
}
func (f *diffRouter) actual() Actual {
	a := Actual{Generation: f.gen, Topology: compilerTopology(), Rows: slices.Clone(f.rows)}
	for i := range a.Rows {
		a.Rows[i].Props = maps.Clone(a.Rows[i].Props)
	}
	return a
}
func (f *diffRouter) CommandAt(ctx context.Context, g uint64, words []string) ([]Row, error) {
	if g == 0 || g != f.gen {
		return nil, ErrStaleGeneration
	}
	if err := validateRequest(words, false); err != nil {
		return nil, err
	}
	path := words[0]
	at := strings.LastIndex(path, "/")
	menu, verb := path[:at], path[at+1:]
	if verb == "print" {
		p := observationPeer{generation: f.gen, rows: map[string][]Row{}}
		for _, r := range f.rows {
			if r.Menu != menu {
				continue
			}
			row := Row(maps.Clone(r.Props))
			row["comment"], row[".id"] = r.Comment, r.ID
			if r.Dynamic {
				row["dynamic"] = "true"
			}
			p.rows[menu] = append(p.rows[menu], row)
		}
		return p.CommandAt(ctx, g, words)
	}
	if f.cutBefore == len(f.writes)+1 {
		f.cutBefore = 0
		f.gen++
		return nil, ErrDisconnected
	}
	props := map[string]string{}
	for _, word := range words[1:] {
		k, v, ok := strings.Cut(strings.TrimPrefix(word, "="), "=")
		if !ok {
			return nil, ErrRequest
		}
		props[k] = v
	}
	id := props[".id"]
	delete(props, ".id")
	tag := props["comment"]
	delete(props, "comment")
	before := props["place-before"]
	delete(props, "place-before")
	if verb == "move" {
		id, before = props["numbers"], props["destination"]
	}
	idx := func(id string) int {
		return slices.IndexFunc(f.rows, func(r Observed) bool { return r.Menu == menu && r.ID == id })
	}
	i := idx(id)
	if verb != "add" && i < 0 {
		return nil, ErrRejected
	}
	var result []Row
	switch verb {
	case "add":
		id = f.insert(menu, tag, props)
		result = []Row{{"ret": id}}
		i = idx(id)
	case "set":
		for k, v := range props {
			if v == "" {
				delete(f.rows[i].Props, k)
			} else {
				f.rows[i].Props[k] = v
			}
		}
	case "move":
	case "remove":
		f.rows = slices.Delete(f.rows, i, i+1)
	default:
		return nil, ErrRejected
	}
	if verb == "move" || before != "" {
		saved := f.rows[i]
		f.rows = slices.Delete(f.rows, i, i+1)
		pos := len(f.rows)
		if before != "" {
			pos = idx(before)
			if pos < 0 {
				return nil, ErrRejected
			}
		}
		f.rows = slices.Insert(f.rows, pos, saved)
	}
	f.writes = append(f.writes, slices.Clone(words))
	if f.afterWrite != nil {
		f.afterWrite()
	}
	if f.lose || f.cutAfter == len(f.writes) {
		f.lose = false
		f.cutAfter = 0
		f.gen++
		return nil, ErrOutcomeUnknown
	}
	return result, nil
}
