// Command tikray-installer binds the production script to one signed image pair.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"

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
	flag.Parse()
	if flag.NArg() != 0 || *dir == "" || *key == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
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
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
