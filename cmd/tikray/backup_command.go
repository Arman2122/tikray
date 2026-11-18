package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/backup"
	"github.com/Arman2122/tikray/internal/service"
)

func (c *cli) statsCommand(ctx context.Context, args []string) int {
	fs := c.newFlagSet("stats", "stats [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON instead of a summary")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Stats(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var st service.Stats
		if err := resp.Decode(&st); err != nil {
			return c.fail(err)
		}
		if !st.Available {
			return c.say("xray stats unavailable")
		}
		tw := c.table()
		if st.Sys != nil {
			fmt.Fprintf(tw, "uptime\t%s\n", (time.Duration(st.Sys.Uptime) * time.Second).String())
			fmt.Fprintf(tw, "goroutines\t%d\n", st.Sys.NumGoroutine)
			fmt.Fprintf(tw, "memory\t%s\n", humanBytes(int64(st.Sys.Alloc)))
		}
		if len(st.Outbounds) > 0 {
			fmt.Fprintln(tw, "\nOUTBOUND\tUPLINK\tDOWNLINK")
			for _, o := range st.Outbounds {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", oneWord(o.Tag), humanBytes(o.Uplink), humanBytes(o.Downlink))
			}
		}
		if len(st.Inbounds) > 0 {
			fmt.Fprintln(tw, "\nINBOUND\tUPLINK\tDOWNLINK")
			for _, in := range st.Inbounds {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", oneWord(in.Tag), humanBytes(in.Uplink), humanBytes(in.Downlink))
			}
		}
		if err := tw.Flush(); err != nil {
			return c.fail(err)
		}
		return 0
	})
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (c *cli) backupCommand(ctx context.Context, args []string) int {
	return c.subcommands("backup", args, map[string]func([]string) int{
		"export":  func(args []string) int { return c.backupExport(ctx, args) },
		"restore": func(args []string) int { return c.backupRestore(ctx, args) },
	})
}

// readBackupPassphrase gets the passphrase from TIKRAY_BACKUP_PASSPHRASE or
// stdin (never a CLI flag, so it stays out of process listings and shell
// history).
func (c *cli) readBackupPassphrase() (string, error) {
	if p := c.getenv("TIKRAY_BACKUP_PASSPHRASE"); p != "" {
		return p, nil
	}
	r := c.stdin
	if r == nil {
		r = os.Stdin
	}
	line, err := bufio.NewReader(io.LimitReader(r, backup.MaxPassLen+8)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("could not read backup passphrase from stdin")
	}
	pass := strings.TrimRight(line, "\r\n")
	if len(pass) < backup.MinPassLen {
		return "", fmt.Errorf("backup passphrase must be at least %d characters (set TIKRAY_BACKUP_PASSPHRASE or pipe via stdin)", backup.MinPassLen)
	}
	return pass, nil
}

func (c *cli) backupExport(ctx context.Context, args []string) int {
	fs := c.newFlagSet("backup export", "backup export --out FILE")
	outPath := fs.String("out", "", "path to write the encrypted backup JSON (`FILE`)")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	if strings.TrimSpace(*outPath) == "" {
		return c.flagError(fs, "--out FILE is required")
	}
	pass, err := c.readBackupPassphrase()
	if err != nil {
		return c.fail(err)
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.ExportBackup(ctx, pass)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var b backup.Bundle
		if err := resp.Decode(&b); err != nil {
			return c.fail(err)
		}
		pretty, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return c.fail(err)
		}
		pretty = append(pretty, '\n')
		if err := atomicfile.WriteFile(*outPath, pretty, 0o600); err != nil {
			return c.fail(fmt.Errorf("writing backup file: %w", err))
		}
		return c.say("wrote encrypted backup to %s", *outPath)
	})
}

func (c *cli) backupRestore(ctx context.Context, args []string) int {
	fs := c.newFlagSet("backup restore", "backup restore --in FILE")
	inPath := fs.String("in", "", "path of the encrypted backup JSON (`FILE`)")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	if strings.TrimSpace(*inPath) == "" {
		return c.flagError(fs, "--in FILE is required")
	}
	pass, err := c.readBackupPassphrase()
	if err != nil {
		return c.fail(err)
	}
	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return c.fail(fmt.Errorf("reading backup file: %w", err))
	}
	if len(raw) > backup.MaxBundleBytes {
		return c.fail(errors.New("backup file exceeds maximum allowed size"))
	}
	var b backup.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return c.fail(errors.New("backup file is not valid JSON"))
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.RestoreBackup(ctx, b, pass)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var out struct {
			Revision uint64 `json:"revision"`
		}
		_ = resp.Decode(&out)
		return c.say("restored encrypted backup (revision %d)", out.Revision)
	})
}
