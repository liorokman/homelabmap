package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// reverseDNS resolves PTR names using the host's resolver.
func reverseDNS(ctx context.Context, ips []string) map[string]string {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 32)
		out = map[string]string{}
	)
	for _, ip := range ips {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(lctx, ip)
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			out[ip] = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}
