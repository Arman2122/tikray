package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/atomicfile"
)

// An owner import leaves a new public nonce. Idle ticks only read the file;
// the durable claim precedes the single live attempt, including after restart.
// No session credentials are used
// for the HTTPS probe and no diagnostics from either peer go into the proof.
func watchInstallChecks(ctx context.Context, data, endpoint, pin string, verify func(context.Context) error) {
	last := ""
	wait := 2 * time.Second
	for ctx.Err() == nil {
		check, cancel := context.WithTimeout(ctx, 45*time.Second)
		done, err := checkInstallation(check, data, endpoint, pin, last, verify)
		cancel()
		last = done
		if err == nil {
			wait = 2 * time.Second
		} else {
			wait = min(2*wait, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func checkInstallation(ctx context.Context, data, endpoint, pin, last string, verify func(context.Context) error) (string, error) {
	path := filepath.Join(data, "install.check")
	b, err := atomicfile.ReadRegular(path, 32, 0)
	if errors.Is(err, os.ErrNotExist) {
		return last, nil
	}
	nonce := string(b)
	if err != nil || len(nonce) != 32 || nonce != strings.ToLower(nonce) {
		return last, errInstall
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return last, errInstall
	}
	if nonce == last {
		return last, nil
	}
	dir := stateDir(data)
	proof := filepath.Join(dir, "install.checked")
	// A previous image may have acknowledged the challenge without a claim.
	acked, err := atomicfile.ReadRegular(proof, 97, 0600)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return last, errInstall
	}
	if strings.HasPrefix(string(acked), nonce+" ") {
		return nonce, nil
	}
	claim := filepath.Join(dir, "install.attempt")
	attempted, err := atomicfile.ReadRegular(claim, 32, 0600)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return last, errInstall
	}
	if string(attempted) == nonce {
		return nonce, nil
	}
	// A power cut after this sync or a timed-out verifier consumes the
	// request. Only another owner import can authorize a new login.
	if err := atomicfile.WriteFile(claim, b, 0600); err != nil {
		return last, errInstall
	}
	client := apiclient.Client{BaseURL: endpoint, Fingerprint: pin}
	if client.Healthz(ctx) != nil || verify(ctx) != nil {
		return nonce, errInstall
	}
	current, err := atomicfile.ReadRegular(path, 32, 0)
	if err != nil || string(current) != nonce {
		return nonce, errInstall
	}
	if ctx.Err() != nil || atomicfile.WriteFile(proof, []byte(nonce+" "+pin), 0600) != nil {
		return nonce, errInstall
	}
	return nonce, nil
}
