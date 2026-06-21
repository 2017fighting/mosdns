package cfst_pool

import (
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/cfst_pool/internal/runner"
)

// Plugin is a long-lived cfst_pool instance. It holds the most recent
// FastIPSet behind an atomic pointer for lock-free reads.
type Plugin struct {
	args    Args
	runner  runner.Runner
	current atomic.Pointer[data_provider.FastIPSet]

	stopCh chan struct{}
	doneCh chan struct{}
}

// GetFastIPs returns the current snapshot. Always non-nil after Init.
func (p *Plugin) GetFastIPs() data_provider.FastIPSet {
	set := p.current.Load()
	if set == nil {
		return data_provider.FastIPSet{}
	}
	return *set
}

// Close stops the refresh loop and signal handler. Safe to call multiple times.
func (p *Plugin) Close() error {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
	<-p.doneCh
	return nil
}
