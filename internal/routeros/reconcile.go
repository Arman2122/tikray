package routeros

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

type Native interface {
	Generation() uint64
	CommandAt(context.Context, uint64, []string) ([]Row, error)
	Listen(context.Context, []string, func(Change)) error
}
type InstallScope struct {
	Subnet    netip.Prefix   `json:"subnet"`
	LANList   string         `json:"lan_list"`
	LANs      []LAN          `json:"lans"`
	WAN       WANPath        `json:"wan"`
	LocalLANs []netip.Prefix `json:"local_lans,omitempty"`
}
type LeaseInfo struct {
	Address              netip.Addr
	MAC, Name, Interface string
}
type Observed struct {
	Menu, ID, Comment string
	Props             map[string]string
	Dynamic           bool
}
type Actual struct {
	Generation    uint64
	Topology      Topology
	Rows          []Observed
	Leases        []LeaseInfo
	IPv6FastTrack bool
}
type Target struct {
	Policy    PolicyInput
	Revision  uint64
	Selection runnerapi.Selection
	Geo       []netip.Prefix
	Verify    func(context.Context) error `json:"-"`
}
type Report struct {
	Added, Set, Moved, Removed, Invalidated int
	Revision                                uint64
}

var (
	ErrPolicyConflict = errors.New("routeros: policy or ownership conflict")
	ErrUnavailable    = errors.New("routeros: verified router state unavailable")
)
