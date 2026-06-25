# cfst_pool: Reuse Previous Election Results — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cfst_pool re-enter the previously-elected IPs (`p.current`) into each scan as candidates that are re-measured and survive only on merit, so the pool stops churning every refresh when conditions are stable.

**Architecture:** Add a `Previous dp.FastIPSet` field to `runner.Runner`. The plugin's `refresh()` copies the runner value, sets `Previous` from `p.current`, and calls `Run`. Inside `Run`, a new `mergePrevious` helper folds those addrs into the fresh candidate pool (dedup + family guard) right after sampling; everything downstream (TCP → download → score) is unchanged.

**Tech Stack:** Go (stdlib `net/netip`, `sort`, `go.uber.org/zap`), `go test -race`. No new dependencies.

## Global Constraints

- **No config toggle.** Always-on. Do not touch `args.go`, `args_test.go`, `configs/cfst_pool.yaml`, or any user-facing doc/config.
- **Re-measure, pure merit.** Previous winners are candidates, not guaranteed seats. No hysteresis / grace period.
- **Concurrency:** `p.runner` is a value written once in `Init` and read-only afterward; per-call state must be written to a **local copy** — no mutex.
- **CIDR excludes are NOT re-applied** to previous winners (out of scope).
- **Download-probe budget unchanged:** do not raise the `topN` cap.
- **TDD:** write the failing test first, watch it fail, implement, watch it pass, commit. Run the whole package with `-race`.
- **Commits:** conventional-commit format (`feat`/`test`/`refactor`/`docs`). Attribution is disabled globally — do not add Co-Authored-By trailers.

## File Structure

- `plugin/data_provider/cfst_pool/internal/runner/runner.go` — add `Previous` field to `Runner`; add `mergePrevious` helper; two merge call-sites in `Run`; extend the `sampled candidates` log. (Existing file, 395 lines; this adds ~40.)
- `plugin/data_provider/cfst_pool/internal/runner/runner_test.go` — add `TestMergePrevious_*`, `TestRun_PreviousResultsCompeteAndWin`, `TestRun_PreviousUnreachableDropped`. Add `net/netip` and `dp` imports.
- `plugin/data_provider/cfst_pool/init.go` — 3-line wiring in `refresh()` (local copy + set `Previous`).

The runner package already imports `dp "github.com/IrineSistiana/mosdns/v5/plugin/data_provider"` and `"net/netip"`, so `Runner.Previous dp.FastIPSet` adds no new import to `runner.go`.

---

### Task 1: `mergePrevious` helper (TDD)

**Files:**
- Modify: `plugin/data_provider/cfst_pool/internal/runner/runner.go` (add helper near the bottom, after `probeDownloads`)
- Test: `plugin/data_provider/cfst_pool/internal/runner/runner_test.go` (add `TestMergePrevious_*`)

**Interfaces:**
- Produces: `func mergePrevious(fresh, previous []netip.Addr) ([]netip.Addr, int)` — used by Task 2.

- [ ] **Step 1: Write the failing tests**

Append to `runner_test.go`. Also add the two imports the new tests need (`net/netip` and the `dp` package) to the existing import block.

Add to the import block:
```go
	"net/netip"

	dp "github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
```

Append these tests:
```go
func TestMergePrevious_EmptyPreviousIsPassthrough(t *testing.T) {
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	out, added := mergePrevious(fresh, nil)
	if added != 0 {
		t.Errorf("added = %d, want 0", added)
	}
	if len(out) != 1 || out[0] != fresh[0] {
		t.Errorf("out = %v, want %v unchanged", out, fresh)
	}
}

func TestMergePrevious_AppendsNewAddrsAndCounts(t *testing.T) {
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	prev := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"), // dup → skipped
		netip.MustParseAddr("1.1.1.2"), // new → added
		netip.MustParseAddr("1.1.1.3"), // new → added
	}
	out, added := mergePrevious(fresh, prev)
	if added != 2 {
		t.Fatalf("added = %d, want 2", added)
	}
	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3", len(out))
	}
	// Order: fresh first, then appended previous in order.
	want := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("out[%d] = %v, want %v", i, out[i], want[i])
		}
	}
}

func TestMergePrevious_FamilyGuardDropsCrossFamily(t *testing.T) {
	// Fresh is v4; a v6 previous addr must be skipped, not dialed on the v4 pool.
	fresh := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	prev := []netip.Addr{
		netip.MustParseAddr("2606:4700::1"), // cross-family → skipped
		netip.MustParseAddr("1.1.1.2"),      // same family → added
	}
	out, added := mergePrevious(fresh, prev)
	if added != 1 {
		t.Fatalf("added = %d, want 1 (cross-family skipped)", added)
	}
	for _, a := range out {
		if a.Is6() {
			t.Errorf("v6 addr %v leaked into v4 pool", a)
		}
	}
}

func TestMergePrevious_FreshEmptyInfersFamilyFromPrevious(t *testing.T) {
	// No fresh sample; family taken from previous. v6 previous all kept.
	prev := []netip.Addr{
		netip.MustParseAddr("2606:4700::1"),
		netip.MustParseAddr("2606:4700::2"),
	}
	out, added := mergePrevious(nil, prev)
	if added != 2 {
		t.Fatalf("added = %d, want 2", added)
	}
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
}

func TestMergePrevious_BothEmptyReturnsNil(t *testing.T) {
	out, added := mergePrevious(nil, nil)
	if added != 0 || out != nil {
		t.Errorf("out = %v added = %d, want nil/0", out, added)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./plugin/data_provider/cfst_pool/internal/runner/ -run TestMergePrevious -race`
Expected: FAIL — compile error `undefined: mergePrevious`.

- [ ] **Step 3: Implement `mergePrevious`**

Append to `runner.go` (after the `probeDownloads` function):
```go
// mergePrevious folds previous addrs into the fresh candidate pool, returning
// the merged slice and the number of previous addrs actually added. A previous
// addr is appended only if it is not already present in fresh (dedup) and
// matches the pool's family.
//
// The expected family is taken from the first addr in fresh, or — when fresh
// is empty — the first addr in previous. Both inputs are single-family by
// construction (v4 pools come from v4 CIDRs; the caller passes Previous.IPv4
// and Previous.IPv6 separately, already split), so this is well-defined. When
// both are empty the result is (nil, 0).
//
// This lets the previously-elected IPs re-enter the next scan as candidates so
// a still-good IP is not dropped merely because the random sampler did not
// re-draw it this round.
func mergePrevious(fresh, previous []netip.Addr) ([]netip.Addr, int) {
	if len(previous) == 0 {
		return fresh, 0
	}
	wantV6 := false
	switch {
	case len(fresh) > 0:
		wantV6 = fresh[0].Is6()
	default:
		wantV6 = previous[0].Is6()
	}
	seen := make(map[netip.Addr]struct{}, len(fresh)+len(previous))
	for _, a := range fresh {
		seen[a] = struct{}{}
	}
	out := fresh
	added := 0
	for _, a := range previous {
		if a.Is6() != wantV6 {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
		added++
	}
	return out, added
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./plugin/data_provider/cfst_pool/internal/runner/ -run TestMergePrevious -race`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add plugin/data_provider/cfst_pool/internal/runner/runner.go plugin/data_provider/cfst_pool/internal/runner/runner_test.go
git commit -m "feat(cfst_pool): add mergePrevious helper for reusing prior winners"
```

---

### Task 2: Wire `Previous` field + merge into `Run` + extend log (TDD)

**Files:**
- Modify: `plugin/data_provider/cfst_pool/internal/runner/runner.go` (add field to `Runner`; merge call-sites in `Run`; log fields)
- Test: `plugin/data_provider/cfst_pool/internal/runner/runner_test.go` (add two `Run`-level tests)

**Interfaces:**
- Consumes: `mergePrevious` from Task 1.
- Produces: `Runner.Previous dp.FastIPSet` — set per-call by the plugin (Task 3).

- [ ] **Step 1: Add the `Previous` field to the `Runner` struct**

In `runner.go`, find the `SampleMode string` field (around line 71) and insert this block immediately after its doc comment + field (i.e., before the `FWMark` field):

```go
	// Previous holds the previously-elected IPs that should re-enter this scan
	// as candidates (re-measured, not carried over). Empty on the first scan.
	// Set per-call by the plugin from its current FastIPSet; defaults to empty
	// so a Runner with Previous == zero value behaves exactly as before.
	Previous dp.FastIPSet
```

- [ ] **Step 2: Write the failing `Run`-level test**

Append to `runner_test.go`:
```go
// TestRun_PreviousResultsCompeteAndWin proves Previous re-enters the election:
// the fresh sample (192.0.2.0/30, RFC 5737 TEST-NET-1) is entirely unreachable,
// so the ONLY way Run returns a non-empty set is if Previous is merged in and
// wins on merit. Without the merge, Run returns an empty IPv4 set.
func TestRun_PreviousResultsCompeteAndWin(t *testing.T) {
	payload := strings.Repeat("x", 256*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	r := Runner{
		CIDRs:           []string{"192.0.2.0/30"},
		Port:            port,
		PingTimes:       1,
		Routines:        1,
		TCPTimeout:      500 * time.Millisecond,
		HTTPS:           false,
		DownloadURL:     srv.URL,
		DownloadTimeout: time.Second,
		TopN:            1,
		Seed:            42,
		SampleCount:     1,
		Previous: dp.FastIPSet{
			IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		},
	}

	set, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := netip.MustParseAddr("127.0.0.1")
	if len(set.IPv4) != 1 || set.IPv4[0] != want {
		t.Fatalf("expected Previous 127.0.0.1 to win; got %v", set.IPv4)
	}
}

// TestRun_PreviousUnreachableDropped is a regression guard: when the fresh
// sample is reachable and a Previous addr is not, the Previous addr must be
// absent from the result (pure merit — no carry-over).
func TestRun_PreviousUnreachableDropped(t *testing.T) {
	payload := strings.Repeat("x", 256*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	r := Runner{
		CIDRs:           []string{"127.0.0.1/32"},
		Port:            port,
		PingTimes:       1,
		Routines:        1,
		TCPTimeout:      500 * time.Millisecond,
		HTTPS:           false,
		DownloadURL:     srv.URL,
		DownloadTimeout: time.Second,
		TopN:            1,
		Seed:            42,
		SampleCount:     1,
		Previous: dp.FastIPSet{
			IPv4: []netip.Addr{netip.MustParseAddr("192.0.2.7")},
		},
	}

	set, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := netip.MustParseAddr("127.0.0.1")
	if len(set.IPv4) != 1 || set.IPv4[0] != want {
		t.Fatalf("expected only reachable 127.0.0.1; got %v", set.IPv4)
	}
	dropped := netip.MustParseAddr("192.0.2.7")
	for _, ip := range set.IPv4 {
		if ip == dropped {
			t.Fatalf("unreachable Previous addr %v must be dropped, not elected", dropped)
		}
	}
}
```

- [ ] **Step 3: Run the new test to verify it fails**

Run: `go test ./plugin/data_provider/cfst_pool/internal/runner/ -run TestRun_PreviousResultsCompeteAndWin -race`
Expected: FAIL — `expected Previous 127.0.0.1 to win; got []` (Previous is ignored, fresh sample unreachable → empty set). `TestRun_PreviousUnreachableDropped` should PASS already (it does not depend on the merge); that is expected.

- [ ] **Step 4: Wire the merge into `Run` and extend the log**

In `runner.go`, locate the `sampled candidates` log call inside `Run` (around line 185):
```go
	log.Info("cfst_pool: sampled candidates",
		zap.Int("v4", len(v4Addrs)),
		zap.Int("v6", len(v6Addrs)),
	)
```
Replace that log call (and insert the merge immediately before it) with:
```go
	// Fold previously-elected IPs into the candidate pool so they re-enter this
	// election on equal footing (re-measured downstream, not carried over).
	v4PrevCount, v6PrevCount := 0, 0
	v4Addrs, v4PrevCount = mergePrevious(v4Addrs, r.Previous.IPv4)
	if r.IPv6 {
		v6Addrs, v6PrevCount = mergePrevious(v6Addrs, r.Previous.IPv6)
	}

	log.Info("cfst_pool: sampled candidates",
		zap.Int("v4", len(v4Addrs)),
		zap.Int("v6", len(v6Addrs)),
		zap.Int("v4_previous", v4PrevCount),
		zap.Int("v6_previous", v6PrevCount),
	)
```
(`v4`/`v6` are the merged totals; `v4_previous`/`v6_previous` are how many came from `Previous`. The download probe's `topN` cap is unchanged, so wall-clock cost does not grow.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./plugin/data_provider/cfst_pool/internal/runner/ -race`
Expected: PASS — all runner tests, including both new `Run`-level tests.

- [ ] **Step 6: Commit**

```bash
git add plugin/data_provider/cfst_pool/internal/runner/runner.go plugin/data_provider/cfst_pool/internal/runner/runner_test.go
git commit -m "feat(cfst_pool): merge previous winners into each scan's candidate pool"
```

---

### Task 3: Forward `p.current` into `Previous` from `refresh()` (wiring)

**Files:**
- Modify: `plugin/data_provider/cfst_pool/init.go:181` (first lines of `refresh()`)

**Interfaces:**
- Consumes: `Runner.Previous` from Task 2.
- Produces: end-to-end behavior — the served set re-enters the next scan.

This is a 3-line wiring change. It is verified by the **existing** init tests rather than a new one, for two honest reasons: (1) `TestInitCacheLoadFail` already loads a cache into `p.current` *before* the cold-start refresh runs, so after this change that refresh exercises the new `r.Previous = *cur` branch; (2) a dedicated wiring assertion is impractical because the existing "empty scan keeps last set" guard would mask a broken Previous path (a failed scan would retain the seeded set either way), and the single-loopback test fixture cannot produce two distinct reachable IPs. The behavioral proof of the feature lives in Task 2's runner-level tests.

- [ ] **Step 1: Make the wiring change**

In `init.go`, replace the first two lines of `refresh()`:
```go
func (p *Plugin) refresh(ctx context.Context, bp *coremain.BP) {
	set, err := p.runner.Run(ctx)
```
with:
```go
func (p *Plugin) refresh(ctx context.Context, bp *coremain.BP) {
	// Forward the currently-served set so last round's winners re-enter this
	// scan as candidates and survive only on merit. Copy p.runner (a value)
	// and set Previous on the local copy — p.runner itself stays read-only,
	// so the ticker and SIGUSR1 goroutines can call refresh concurrently with
	// no mutex. p.current.Load() is atomic and the FastIPSet it points at is
	// replaced via Store, never mutated in place, so *cur is safe to read.
	r := p.runner
	if cur := p.current.Load(); cur != nil {
		r.Previous = *cur
	}
	set, err := r.Run(ctx)
```

- [ ] **Step 2: Build and vet**

Run: `go build ./... && go vet ./plugin/data_provider/cfst_pool/...`
Expected: no output (success).

- [ ] **Step 3: Run the full cfst_pool suite with race detection**

Run: `go test ./plugin/data_provider/cfst_pool/... -race`
Expected: PASS — including `TestInitCacheLoadFail` (which now exercises the `r.Previous = *cur` branch) and `TestCloseAbortsInFlightScan`.

- [ ] **Step 4: Commit**

```bash
git add plugin/data_provider/cfst_pool/init.go
git commit -m "feat(cfst_pool): forward current set as Previous candidates in refresh"
```

---

## Final Verification

- [ ] **Whole-package race test:** `go test ./plugin/data_provider/cfst_pool/... -race` → all PASS.
- [ ] **Build + vet:** `go build ./... && go vet ./...` → clean.
- [ ] **Confirm scope:** `git diff main --stat` touches only `runner.go`, `runner_test.go`, `init.go` (no `args.go`, config, or doc changes).
