# cfst_pool: Reuse Previous Election Results in Next Scan

**Date:** 2026-06-25
**Branch:** `feat/cfst-pool-reuse-previous-results`
**Status:** Approved (design) → implementation plan pending

## Goal

Each cfst_pool refresh currently samples a *fresh* random set of candidate IPs,
measures them, and **completely replaces** the served set (`p.current`). An IP
that was elected last round but simply was not re-sampled this round is dropped —
so the pool churns every refresh even when network conditions are stable.

This change makes the **previously-elected IPs re-enter the next scan as
candidates**, re-measured on equal footing with the fresh sample, surviving only
on merit. The pool stays stable across refreshes and only churns when an IP
genuinely degrades or a better one appears.

## Decisions (confirmed with user)

- **Mechanism:** Re-measure previous winners as candidates, **pure merit**. They
  join the fresh sample, run through TCP + download probes, and compete. Still-good
  IPs stay; degraded/unreachable ones drop. No hysteresis / grace period.
- **Config:** Always-on, **no toggle** (YAGNI). No new `args` field, config key,
  or doc/config-example changes.

## Background — how the election works today

`Plugin.refresh()` (`plugin/data_provider/cfst_pool/init.go`) calls
`runner.Run(ctx)`. `Run` (`internal/runner/runner.go`) executes:

1. **Sample** CIDRs → candidate IPs (random subset or cfst `/24` walk).
2. **TCP probe** all candidates (latency).
3. **Download probe** the top-`topN` by lowest RTT, **sequentially** (Cloudflare
   WAF rate-limits parallel requests).
4. **Score** by `BytesPerSec` descending; `scorer.SelectTopN` returns `topN`.
5. Returns a `dp.FastIPSet` (split IPv4/IPv6).

`refresh()` atomically `Store`s the new set into `p.current`, replacing the
previous one entirely. There is an existing guard: if a scan returns empty, the
last good set is kept.

`runner.Run` is the only entry point, called from `init.go:refresh()` and from
`internal/runner/runner_test.go` (4 call sites, all `Runner{}` struct literals).
`Plugin.runner` is a `runner.Runner` **value** written once in `Init`, read-only
afterward. `p.current` is an atomic pointer to a `dp.FastIPSet` that is replaced
via `Store`, never mutated in place.

## Design

### 1. Plumbing — a new field on `Runner`

Add `Previous dp.FastIPSet` to the `Runner` struct. This is consistent with the
existing idiom (all knobs — `TopN`, `SampleCount`, `Log` — are struct fields),
defaults to empty (= today's behavior), and requires no test changes.

`refresh()` builds a **local copy** of the runner, sets `.Previous` from
`p.current`, and calls `Run`:

```go
func (p *Plugin) refresh(ctx context.Context, bp *coremain.BP) {
    r := p.runner                       // local copy; never mutates p.runner
    if cur := p.current.Load(); cur != nil {
        r.Previous = *cur               // safe: *cur is never mutated in place
    }
    set, err := r.Run(ctx)
    // ... unchanged error / empty-set / Store / persist handling
}
```

Rejected alternative: changing `Run(ctx)` → `Run(ctx, previous)`. More explicit
but breaks all 4 test call sites and diverges from the established pattern.

### 2. Merge logic — `runner.Run`, after sampling, before TCP probe

```go
v4PrevCount, v6PrevCount := 0, 0
v4Addrs, v4PrevCount = mergePrevious(v4Addrs, r.Previous.IPv4)
if r.IPv6 {
    v6Addrs, v6PrevCount = mergePrevious(v6Addrs, r.Previous.IPv6)
}
```

`mergePrevious` is a small extracted, unit-tested helper:

```go
// mergePrevious appends each previous addr not already present in fresh
// (dedup) and matching the pool's family, returning the merged slice and
// the count of previous addrs actually added. An empty previous slice is a
// no-op (cold start == today's behavior).
func mergePrevious(fresh, previous []netip.Addr) ([]netip.Addr, int)
```

Behavior:
- Dedup via `map[netip.Addr]struct{}` keyed on the addr value.
- **Family guard (defensive):** the expected family is the family of the first
  addr in `fresh`, or — when `fresh` is empty — the family of the first addr in
  `previous`. (Both inputs are single-family by construction: `v4Addrs` comes
  from v4 CIDRs only, and the caller passes `Previous.IPv4` / `Previous.IPv6`
  separately, already split by `FastIPSet`.) Skip any `previous` addr whose
  family differs from expected, so a stray cross-family addr is never dialed on
  the wrong family by the TCP probe. When both `fresh` and `previous` are empty,
  return `(nil, 0)`.
- Return `(merged, addedCount)` so the stage log can report how many previous
  candidates entered the election.

Everything downstream is **unchanged**: TCP probe → download probe (capped at
`topN` by RTT → **no wall-clock cost increase**) → `scorer.SelectTopN`.

### 3. Logging

Extend the existing `cfst_pool: sampled candidates` Info log with the previous
counts so an operator can see that reuse is happening:

```go
log.Info("cfst_pool: sampled candidates",
    zap.Int("v4", len(v4Addrs)),
    zap.Int("v6", len(v6Addrs)),
    zap.Int("v4_previous", v4PrevCount),
    zap.Int("v6_previous", v6PrevCount),
)
```

### 4. Concurrency safety

- `p.runner` is written once in `Init`; all later access (from the ticker and
  signal-handler goroutines) is read-only → concurrent reads are race-free, no
  mutex needed. Per-call state is written to a **local copy**.
- `p.current.Load()` is atomic; the pointed-to `FastIPSet` is replaced via
  `Store`, never mutated in place → reading `*cur` is safe.
- Pre-existing concurrent-refresh consideration (ticker + SIGUSR1 overlap) is
  unchanged by this feature; each refresh reads whatever `p.current` holds at
  call time.

## Edge cases & non-goals

- **Cold start** (`p.current == nil`): `Previous` empty → no injection →
  identical to today.
- **Cache-loaded start:** cached winners are re-validated on the **first** scan.
  Stale/bad cached IPs get dropped by merit rather than served until the next
  tick. This is a bonus, not a risk.
- **CIDR excludes are NOT re-applied** to previous winners (non-goal). Rationale:
  the built-in WARP/gateway excludes fail at the *download* stage, so such IPs
  could never have been elected; real previous winners do not fall in those
  ranges. Re-filtering adds coupling for no practical benefit (YAGNI).
- **No hysteresis:** a previous winner that fails this round is dropped
  immediately (per the pure-merit decision).
- **Download budget unchanged:** the `topN` cap on the download probe is not
  raised. Injecting ≤~`topN` previous winners into the TCP stage is trivial; the
  sequential download-probe count does not grow.

## Testing (TDD)

All under `internal/runner/`, run with `go test -race`.

1. **`TestMergePrevious_*`** (unit, on the helper): dedup, family guard, empty
   `previous` is a passthrough, `addedCount` correctness.
2. **`TestRun_PreviousResultsCompeteAndWin`**: fresh sample yields only an
   *unreachable* IP (CIDR `192.0.2.0/30`, RFC 5737 TEST-NET-1); `Previous.IPv4`
   contains the loopback addr of an `httptest` server → assert
   `set.IPv4 == [127.0.0.1]`. Proves previous results enter the election and win
   on merit when the fresh sample finds nothing.
3. **`TestRun_PreviousUnreachableDropped`**: fresh sample has the reachable
   loopback; `Previous.IPv4` holds an unreachable addr → assert the unreachable
   previous addr is absent from the result (pure merit).

Existing tests are unchanged (new optional field defaults to empty).

## Files touched

- `plugin/data_provider/cfst_pool/internal/runner/runner.go` — add `Previous`
  field, `mergePrevious` helper, two merge call-sites, log fields.
- `plugin/data_provider/cfst_pool/internal/runner/runner_test.go` — add the
  tests above.
- `plugin/data_provider/cfst_pool/init.go` — the `refresh()` wiring (local copy
  + set `Previous`).

No changes to `args.go`, `args_test.go`, `configs/cfst_pool.yaml`, or docs (no
new knob).

## Out of scope

- Config toggle for reuse behavior.
- Hysteresis / failure-grace periods.
- Re-applying CIDR excludes to previous winners.
- Reusing prior *measurements* (skipping re-probe) — explicitly rejected; reuse
  means re-measure.
