package artifacts

import "context"

// GeoReleaseAvailable compares the immutable active slot with the trusted
// publisher's latest release identity. Read no candidate assets in notify mode.
func (u *CoreUpdater) GeoReleaseAvailable(ctx context.Context, profile, active string) (bool, error) {
	if active != "" {
		if _, _, err := verifiedGeo(u.Data, active); err != nil {
			return false, err
		}
	}
	release, err := u.resolveGeo(ctx, profile, "latest")
	if err != nil {
		return false, err
	}
	return active != release.slot, nil
}
