package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// MAC addresses given to CHR's NICs, so provisioning can check that the WAN
// tap really became ether1.
const (
	macWAN = "52:54:00:7a:00:01"
	macLAN = "52:54:00:7a:00:02"
)

// BootOptions configures one CHR VM.
type BootOptions struct {
	Version    string
	Arch       Arch
	Artifacts  Artifacts
	WorkDir    string
	Password   string
	MemoryMB   int
	DataDiskMB int
}

// CHR is a running RouterOS CHR VM attached to the lab network: ether1 on the
// WAN bridge at 198.51.100.2, ether2 on the LAN bridge at 192.168.88.1.
type CHR struct {
	opts   BootOptions
	cmd    *exec.Cmd
	exited chan struct{}
	con    *console
	ssh    *ssh.ClientConfig
	hlog   *os.File
}

// logf writes a timestamped line to WorkDir/harness.log, the timeline to read
// next to console.log when a boot goes wrong.
func (c *CHR) logf(format string, args ...any) {
	if c.hlog != nil {
		fmt.Fprintf(c.hlog, "%s "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, args...)...)
	}
}

// BootCHR copies the CHR image into WorkDir, boots it with an empty data disk,
// sets the admin password and lab addresses over the serial console, and
// returns once SSH answers.
func BootCHR(ctx context.Context, n *Network, opts BootOptions) (*CHR, error) {
	if opts.MemoryMB == 0 {
		opts.MemoryMB = 1024
	}
	if opts.DataDiskMB == 0 {
		opts.DataDiskMB = 2048
	}
	if err := os.MkdirAll(opts.WorkDir, 0o755); err != nil {
		return nil, err
	}
	sys := filepath.Join(opts.WorkDir, "system.qcow2")
	data := filepath.Join(opts.WorkDir, "data.qcow2")
	if err := run(ctx, "qemu-img", "convert", "-O", "qcow2", opts.Artifacts.DiskImage, sys); err != nil {
		return nil, err
	}
	if err := run(ctx, "qemu-img", "create", "-q", "-f", "qcow2", data, strconv.Itoa(opts.DataDiskMB)+"M"); err != nil {
		return nil, err
	}
	c := &CHR{
		opts: opts,
		ssh: &ssh.ClientConfig{
			User:            "admin+ct",
			Auth:            []ssh.AuthMethod{ssh.Password(opts.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		},
	}
	hlog, err := os.OpenFile(filepath.Join(opts.WorkDir, "harness.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	c.hlog = hlog
	if err := c.start(ctx); err != nil {
		return nil, err
	}
	if err := c.provision(ctx); err != nil {
		c.Shutdown()
		return nil, fmt.Errorf("provision CHR %s %s: %w (console log: %s)", opts.Version, opts.Arch,
			err, filepath.Join(opts.WorkDir, "console.log"))
	}
	return c, nil
}

// bootTimeout is how long one boot may take. CHR runs under TCG emulation
// (no KVM): x86_64 reaches the login prompt in about two minutes.
func (c *CHR) bootTimeout() time.Duration {
	if c.opts.Arch == ArchARM64 {
		return 40 * time.Minute
	}
	return 10 * time.Minute
}

func (c *CHR) qemuArgs() []string {
	w := c.opts.WorkDir
	common := []string{
		"-m", strconv.Itoa(c.opts.MemoryMB), "-smp", "2", "-nographic",
		"-drive", "file=" + filepath.Join(w, "system.qcow2") + ",if=virtio",
		"-drive", "file=" + filepath.Join(w, "data.qcow2") + ",if=virtio",
		"-netdev", "tap,id=wan,ifname=" + TapWAN + ",script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=wan,mac=" + macWAN,
		"-netdev", "tap,id=lan,ifname=" + TapLAN + ",script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=lan,mac=" + macLAN,
		"-serial", "unix:" + filepath.Join(w, "console.sock") + ",server,nowait",
		"-monitor", "none",
	}
	if c.opts.Arch == ArchARM64 {
		return append([]string{"qemu-system-aarch64", "-M", "virt", "-cpu", "max",
			"-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"}, common...)
	}
	return append([]string{"qemu-system-x86_64"}, common...)
}

func (c *CHR) start(ctx context.Context) error {
	logf, err := os.OpenFile(filepath.Join(c.opts.WorkDir, "qemu.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	args := c.qemuArgs()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	c.logf("qemu started: pid %d", cmd.Process.Pid)
	exited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		c.logf("qemu exited: %v", err)
		logf.Close()
		close(exited)
	}()
	c.cmd, c.exited = cmd, exited

	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	con, err := openConsole(dctx, filepath.Join(c.opts.WorkDir, "console.sock"), filepath.Join(c.opts.WorkDir, "console.log"))
	if err != nil {
		c.stop()
		return err
	}
	c.con = con
	return nil
}

func (c *CHR) provision(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.bootTimeout())
	defer cancel()
	if err := c.con.login(ctx, c.opts.Password); err != nil {
		return err
	}
	c.logf("console login done")
	for _, line := range []string{
		"/ip/address/add address=198.51.100.2/24 interface=ether1 comment=lab:wan",
		"/ip/address/add address=192.168.88.1/24 interface=ether2 comment=lab:lan",
		"/ip/route/add gateway=198.51.100.254 comment=lab:default",
		"/ip/service/set ssh disabled=no",
	} {
		if err := c.con.command(ctx, line); err != nil {
			return fmt.Errorf("%s: %w", line, err)
		}
		c.logf("console: %s", line)
	}
	if err := c.waitSSH(ctx); err != nil {
		return err
	}
	mac, err := c.Get(ctx, "/interface/ethernet/get ether1 mac-address")
	if err != nil {
		return err
	}
	if !strings.EqualFold(mac, macWAN) {
		return fmt.Errorf("ether1 has MAC %s, want the WAN NIC %s", mac, macWAN)
	}
	return nil
}

func (c *CHR) stop() {
	if c.cmd == nil {
		return
	}
	c.cmd.Process.Signal(syscall.SIGKILL)
	<-c.exited
	if c.con != nil {
		c.con.close()
		c.con = nil
	}
	c.cmd = nil
}

// Reboot does a soft /system/reboot and waits for SSH to come back.
func (c *CHR) Reboot(ctx context.Context) error {
	c.logf("reboot")
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c.Run(rctx, "/system/reboot")
	cancel()
	if err := c.waitSSHDown(ctx); err != nil {
		return err
	}
	return c.waitSSH(ctx)
}

// PowerCycle kills QEMU (a cold power-off), starts it again on the same
// disks, and waits for SSH.
func (c *CHR) PowerCycle(ctx context.Context) error {
	c.logf("power cycle")
	c.stop()
	if err := c.start(ctx); err != nil {
		return err
	}
	return c.waitSSH(ctx)
}

// Shutdown powers the VM off. It is safe to call more than once.
func (c *CHR) Shutdown() error {
	c.stop()
	if c.hlog != nil {
		c.hlog.Close()
		c.hlog = nil
	}
	return nil
}
