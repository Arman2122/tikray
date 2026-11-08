package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// The root of the control volume accepts only public installer inputs. The
// private copy survives an interrupted upload or a later missing install.json.
type installRequest struct {
	Version     int                   `json:"version"`
	Address     string                `json:"address"`
	Fingerprint string                `json:"fingerprint"`
	Scope       routeros.InstallScope `json:"scope"`
	Core        string                `json:"core"`
	Offline     bool                  `json:"offline,omitempty"`
	ID          string                `json:"installation_id,omitempty"` // set only by the control plane
}

var errInstall = errors.New("tikray: installer handoff is incomplete or conflicts with this installation")

func readRequest(path string, mode os.FileMode) (*installRequest, error) {
	b, err := atomicfile.ReadRegular(path, 1<<20, mode)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errInstall
	}
	var r installRequest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 {
		return nil, errInstall
	}
	if r.Core != "latest" || r.Offline {
		v, err := xrayver.Parse(r.Core)
		if err != nil || v.Less(xrayver.MinTUN) || r.Core != v.String() {
			return nil, errInstall
		}
	}
	r.Fingerprint, err = apiclient.NormalizeFingerprint(r.Fingerprint)
	if err != nil {
		return nil, errInstall
	}
	return &r, nil
}

// openInstallation runs before any renderer, runner client or listener is
// constructed, under the same process lock used for all local state writes.
func openInstallation(data string, db *store.Store) (*installRequest, error) {
	dir := stateDir(data)
	public, err := readRequest(filepath.Join(data, "install.json"), 0)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "install.request")
	private, err := readRequest(path, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(dir, "install.ready")); !errors.Is(err, os.ErrNotExist) {
		if err != nil || private == nil {
			return nil, errInstall
		}
		if _, err := os.Lstat(filepath.Join(dir, "routeros.json")); err != nil {
			return nil, errInstall
		}
	}
	if public == nil && private == nil {
		return nil, nil
	}
	if public != nil && public.ID != "" {
		return nil, errInstall
	}
	if private != nil {
		if private.ID != "" && (len(private.ID) != 32 || strings.Trim(private.ID, "0123456789abcdef") != "") {
			return nil, errInstall
		}
		intent := *private
		intent.ID = ""
		if public != nil && !reflect.DeepEqual(public, &intent) {
			return nil, errInstall
		}
		intent.ID = private.ID
		public = &intent
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, errInstall
	}
	if info.Mode().Perm() != 0700 && os.Chmod(dir, 0700) != nil {
		return nil, errInstall
	}
	st, rev := db.State()
	fresh := rev == 0 && reflect.DeepEqual(st, store.Default())
	if (!fresh && st.Network.Subnet != public.Scope.Subnet) || store.ValidateRouterNetwork(store.Network{Subnet: public.Scope.Subnet}, nil) != nil {
		return nil, errInstall
	}
	in := routeros.Installation{Version: 1, Address: public.Address, Username: "tikray", Fingerprint: public.Fingerprint, Scope: public.Scope}
	recordIntent := func() error {
		// The daemon owns the identity under serve.lock. RouterOS reads a
		// separate, public projection without opening the credential file.
		idPath := filepath.Join(dir, "install.id")
		published, err := atomicfile.ReadRegular(idPath, 32, 0600)
		missing := errors.Is(err, os.ErrNotExist)
		if !missing && (err != nil || public.ID == "" || string(published) != public.ID) {
			return errInstall
		}
		if public.ID == "" {
			var identity [16]byte
			rand.Read(identity[:])
			public.ID = hex.EncodeToString(identity[:])
		}
		if private == nil || private.ID == "" {
			b, err := json.Marshal(public)
			if err != nil || atomicfile.WriteFile(path, b, 0600) != nil {
				return errInstall
			}
		}
		if missing && atomicfile.WriteFile(idPath, []byte(public.ID), 0600) != nil {
			return errInstall
		}
		return nil
	}
	if err := routeros.InitInstallation(data, in, recordIntent); err != nil {
		return nil, errInstall
	}
	if fresh {
		_, _, err = db.Update(rev, func(next *store.State) error {
			next.Network = store.Network{Subnet: public.Scope.Subnet, RequireLocalBridge: true}
			return nil
		})
		if err != nil {
			return nil, errInstall
		}
	}
	return public, nil
}

func (r *installRequest) bootstrapConfig(env Config, fingerprint string) (*service.Bootstrap, error) {
	if r == nil {
		return nil, nil
	}
	path := filepath.Join(stateDir(env.Data), "install.ready")
	b, err := atomicfile.ReadRegular(path, 128, 0600)
	if err == nil {
		if string(b) != fingerprint {
			return nil, errInstall
		}
		return nil, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errInstall
	}
	key := env.IndexPubKeyFile
	if key == "" {
		key = filepath.Join(stateDir(env.Data), "index.pub")
	}
	return &service.Bootstrap{Version: r.Core, Offline: r.Offline, IndexKeyFile: key, Ready: func() error { return atomicfile.WriteFile(path, []byte(fingerprint), 0600) }}, nil
}
