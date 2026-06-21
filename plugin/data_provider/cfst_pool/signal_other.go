//go:build !unix

package cfst_pool

import "os"

// refreshSignals returns nil on platforms without SIGUSR1 (Windows, plan9).
// Refresh-on-signal is a no-op there; cfst_pool's background ticker still
// refreshes on schedule. This keeps the package — and therefore the Windows
// release build — compilable on platforms that have no POSIX user signals,
// mirroring how the internal/sockmark package isolates its Linux-only bits.
func refreshSignals() []os.Signal {
	return nil
}
