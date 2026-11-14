// Command tikray-installer binds the production script to one signed image pair.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

func main() {
	version := flag.String("version", "", "supported RouterOS release")
	arch := flag.String("arch", "", "image architecture (amd64 or arm64)")
	dir := flag.String("images", "", "directory containing both archives and .sig files")
	key := flag.String("key", "", "independently pinned publisher public key file")
	base := flag.String("release-base", "", "public HTTPS release directory for online installation")
	out := flag.String("out", "", "output path for the self-contained install.rsc")
	uninstall := flag.String("uninstall-out", "", "output path for the self-contained owner uninstall.rsc; can be generated separately")
	flag.Parse()
	if flag.NArg() != 0 || (*out == "" && *uninstall == "") || (*out != "" && (*dir == "" || *key == "")) || (*out != "" && *uninstall != "" && filepath.Clean(*out) == filepath.Clean(*uninstall)) {
		flag.Usage()
		os.Exit(2)
	}
	var removal bytes.Buffer
	if *uninstall != "" {
		if err := adapters.BuildUninstaller(&removal); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *out == "" {
		if atomicfile.WriteFile(*uninstall, removal.Bytes(), 0644) != nil {
			fmt.Fprintln(os.Stderr, "installer: cannot write uninstall output")
			os.Exit(1)
		}
		return
	}
	rosarch := *arch
	if rosarch == "amd64" {
		rosarch = "x86_64"
	}
	p, err := adapters.Installed(*version, rosarch, "CHR")
	var images []adapters.VerifiedArchive
	if err == nil {
		for _, name := range []string{"tikray", "tikray-runner"} {
			a, e := adapters.VerifyArchive(context.Background(), p, name, *dir, *key, *base)
			if e != nil {
				err = e
				break
			}
			images = append(images, a)
		}
	}
	var b bytes.Buffer
	if err == nil {
		err = adapters.BuildInstaller(p, images, &b)
	}
	if err == nil && atomicfile.WriteFile(*out, b.Bytes(), 0644) != nil {
		err = fmt.Errorf("installer: cannot write output")
	}
	if err == nil && *uninstall != "" && atomicfile.WriteFile(*uninstall, removal.Bytes(), 0644) != nil {
		err = fmt.Errorf("installer: cannot write uninstall output")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
