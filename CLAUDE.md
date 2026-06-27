# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

**mosdns** — a plugin-oriented DNS forwarder/server.
Go 1.25 · module `github.com/IrineSistiana/mosdns/v5` · GPL-3.0.
Wiki: https://irine-sistiana.gitbook.io/mosdns-wiki/

## Layout

- `main.go` — entry point; delegates to `coremain.Run()` (cobra CLI).
- `coremain/` — CLI runtime and subcommands (`start`, `version`, ...).
- `plugin/` — all plugins, each self-contained and registered via blank import in `main.go`. Active area: `plugin/data_provider/cfst_pool/` (Cloudflare speed-test candidate pool).
- `tools/` — built-in tool plugin (`config.go`, `init.go`, `probe.go`).
- `pkg/`, `mlog/` — shared libraries and logging.
- `configs/` — example configs.
- `scripts/` — helpers (`update_chn_ip_domain.py`, openwrt packaging).
- `release.py` — cross-compile release binaries into `./release/` (darwin/linux, arm/amd64).

## Commands

| Task | Command |
|---|---|
| Build binary | `go build -o mosdns .` |
| Compile-check all | `go build ./...` |
| Build (release, version-stamped) | `go build -ldflags "-s -w -X main.version=$(git describe --tags --long --always)" -trimpath` |
| Run | `go run . start -c <config.yaml> -d <workdir>` (or `./mosdns start ...`) |
| Test | `go test ./...` (add `-race`; `-cover` for coverage) |
| Vet | `go vet ./...` |
| Format | `gofmt -w .` |
| Docker | `docker build -t mosdns .` |

Use `CGO_ENABLED=0` for static binaries (matches the Dockerfile).

## Conventions

- Accept interfaces, return structs; keep interfaces small.
- Wrap errors with context: `fmt.Errorf("failed to ...: %w", err)`.
- Tests are table-driven, stdlib `go test` + `testify`.
- Hot-reload a running mosdns with `SIGUSR1` (`kill -USR1 <pid>`); control API defaults to `127.0.0.1:9091`.
