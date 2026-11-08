// Command routequic runs either half of the disposable QUIC route witness.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "serve" {
		s, e := labinet.StartQUICWitness(os.Args[2], os.Args[3])
		if e == nil {
			_ = labinet.ServeQUICWitness(context.Background(), s)
		}
		os.Exit(1)
	}
	if len(os.Args) == 6 && os.Args[1] == "probe" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		src, dst, sni, e := labinet.ProbeQUIC(ctx, os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		if e == nil {
			fmt.Println(src, dst, sni)
			return
		}
	}
	os.Exit(1)
}
