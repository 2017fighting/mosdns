//go:build unix

package cfst_pool

import (
	"os"
	"syscall"
)

// refreshSignals returns the Unix signals that trigger an immediate cfst_pool
// rescan. SIGUSR1 lets an operator force a refresh — for example after rotating
// the upstream list, or to pick up a fresher IP set without restarting mosdns
// — without waiting for the next ticker tick. cfst_pool's background ticker
// still owns the scheduled refreshes; this only adds an on-demand path.
func refreshSignals() []os.Signal {
	return []os.Signal{syscall.SIGUSR1}
}
