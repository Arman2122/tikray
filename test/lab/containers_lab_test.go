//go:build lab

package lab

import (
	"context"
	"strings"
	"testing"
	"time"
)

// uptimeSeconds parses RouterOS uptime ("1w2d03:04:05", "00:01:30") into
// seconds.
func uptimeSeconds(t *testing.T, s string) int {
	t.Helper()
	total, num := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			num = num*10 + int(r-'0')
		case r == 'w':
			total += num * 7 * 86400
			num = 0
		case r == 'd':
			total += num * 86400
			num = 0
		case r == ':':
			total = (total + num) * 60
			num = 0
		}
	}
	return total + num
}

func TestEnableContainers(t *testing.T) {
	for _, channel := range channels {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
			defer cancel()
			_, c, _ := bootLab(t, ctx, channel)

			if err := c.EnableContainers(ctx); err != nil {
				t.Fatal(err)
			}
			if got, err := c.Get(ctx, "[:len [/system/package/find name=container]]"); err != nil || got != "1" {
				t.Errorf("container packages %q (%v), want 1", got, err)
			}
			mode, err := c.Get(ctx, "/system/device-mode/get container")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("device-mode container = %q", mode)
			if mode != "true" && mode != "yes" {
				t.Errorf("device-mode container %q, want true or yes", mode)
			}
			disks, err := c.Run(ctx, "/disk/print detail")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(disks, "disk1") || !strings.Contains(disks, "ext4") {
				t.Errorf("/disk/print detail lacks an ext4 disk1:\n%s", disks)
			}
			if _, err := c.Run(ctx, "/container/print"); err != nil {
				t.Error(err)
			}

			up1, _ := c.Get(ctx, "/system/resource/get uptime")
			if err := c.EnableContainers(ctx); err != nil {
				t.Fatalf("second EnableContainers: %v", err)
			}
			up2, _ := c.Get(ctx, "/system/resource/get uptime")
			if uptimeSeconds(t, up2) < uptimeSeconds(t, up1) {
				t.Errorf("second EnableContainers rebooted: uptime %s then %s", up1, up2)
			}
		})
	}
}
