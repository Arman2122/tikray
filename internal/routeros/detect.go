package routeros

import (
	"bufio"
	"net"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

// The resource menu is a singleton. Each connection validates its own
// version before being made available to any writer.
func detectProfile(conn net.Conn, r *bufio.Reader) (adapters.Profile, error) {
	resource, err := metadata(conn, r, "resource", "/system/resource/print", "version,architecture-name,board-name")
	if err != nil {
		return adapters.Profile{}, err
	}
	// The updater's requested channel can differ from the installed release.
	p, err := adapters.Installed(resource["version"], resource["architecture-name"], resource["board-name"])
	if err != nil {
		return adapters.Profile{}, ErrUnsupported
	}
	return p, nil
}
func metadata(conn net.Conn, r *bufio.Reader, tag, menu, fields string) (Row, error) {
	data, err := encodeSentence([]string{menu, "=.proplist=" + fields, ".tag=" + tag})
	if err != nil {
		return nil, err
	}
	if writeAll(conn, data) != nil {
		return nil, ErrDisconnected
	}
	var row Row
	for range 32 {
		words, err := readSentence(r)
		if err != nil {
			return nil, safeReadError(err)
		}
		if len(words) == 0 {
			continue
		}
		got, m, err := parseMessage(words)
		if err != nil {
			return nil, err
		}
		if got != tag {
			return nil, ErrProtocol
		}
		switch m.kind {
		case "!re":
			if row != nil {
				return nil, ErrProtocol
			}
			row = m.row
		case "!done":
			if row == nil {
				return nil, ErrUnsupported
			}
			return row, nil
		case "!empty":
		case "!trap":
			return nil, ErrUnsupported
		default:
			return nil, ErrProtocol
		}
	}
	return nil, ErrLimit
}
