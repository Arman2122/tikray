package service

import (
	"context"

	"github.com/Arman2122/tikray/internal/backup"
	"github.com/Arman2122/tikray/internal/store"
)

// ExportBackup encrypts the complete desired state (including server
// credentials and subscription URLs) with passphrase into a portable
// tikray-backup-v1 bundle. The passphrase is never logged or retained.
func (s *Service) ExportBackup(ctx context.Context, passphrase string) (backup.Bundle, error) {
	st, _ := s.store.State()
	b, err := backup.Seal(ctx, st, passphrase)
	if err != nil {
		return backup.Bundle{}, err
	}
	s.record(KindAuth, "exported encrypted backup")
	return b, nil
}

// RestoreBackup decrypts b with passphrase and replaces the desired state
// atomically at revision rev. On managed RouterOS installations (or hosts bound
// to a verified local bridge), the installation's existing bridge subnet is
// preserved so restoring a backup from another router cannot orphan the
// container bridge.
func (s *Service) RestoreBackup(ctx context.Context, rev uint64, b backup.Bundle, passphrase string) (uint64, error) {
	if s.bootPending.Load() {
		return 0, ErrBootstrapPending
	}
	restored, err := backup.Open(ctx, b, passphrase)
	if err != nil {
		return 0, err
	}
	_, next, err := s.change(ctx, rev, func(st *store.State) ([]note, error) {
		if s.router != nil || st.Network.RequireLocalBridge {
			restored.Network = st.Network
		}
		*st = restored
		return []note{{KindAuth, "restored encrypted backup"}}, nil
	})
	return next, err
}
