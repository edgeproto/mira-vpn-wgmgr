# mira-vpn-wgmgr

WireGuard edge manager for Mira VPN: HTTP API to create and delete peers, write client configs, and run `wg set` on a live interface (`real` mode).

This repository is split from the control plane (`mira-vpn-backend`). The API talks to each edge over HTTPS; this binary listens on the edge (usually behind a reverse proxy on port 9090).

## Layout

| Path | Role |
|------|------|
| `cmd/wgmgr` | Entrypoint |
| `internal/wgmgr` | HTTP handlers, mock/real provisioners, env config |
| `pkg/locationregistry` | Location profiles JSON, validation, client config rendering (stdlib-only; safe for the API to import as a Go module) |

## Environment

**Daemon / provisioner**

- `PORT` — HTTP listen port (default `9090`).
- `WGMGR_MODE` — `mock` (default) or `real`.
- `WGMGR_MOCK_*` — mock mode: output directory, endpoint, server public key, DNS, allowed IPs.
- `WGMGR_REAL_*` — real mode: output dir, `wg` interface name, endpoint/key/DNS/allowed IPs fallbacks, dry-run, command timeout.
- `WGMGR_CLIENT_MTU` — optional MTU in generated client configs (default `1280`; `0` omits).

**Location registry** (same semantics as the control plane; ship the same JSON everywhere)

- `WGMGR_LOCATION_PROFILES_FILE` — path to JSON array of profiles (takes precedence).
- `WGMGR_LOCATION_PROFILES_JSON` — inline JSON if file is unset.

## HTTP API

- `GET /health` — returns `200` and body `ok` (for load balancers).
- `POST /v1/peers` — JSON `{"userId":"...","location":"Finland"}`; `201` with peer metadata and WireGuard config.
- `DELETE /v1/peers/{peerID}` — `204` on success.

**Security:** do not expose port 9090 on the public Internet without TLS and authentication. Prefer TLS termination on Caddy or nginx in front of this process, and restrict who can reach the management port.

## Build

```bash
go build -o wgmgr ./cmd/wgmgr
go test ./...
```

## Docker (edge)

```bash
docker compose -f docker-compose.edge.yml up -d --build
```

The compose file uses `network_mode: host` and `NET_ADMIN` so `wg set` can target the host’s WireGuard interface. Mount your location profiles file and set `WGMGR_LOCATION_PROFILES_FILE` when you move beyond the built-in default profile.

## Firewall

- Allow **UDP 51820** (or your chosen WireGuard listen port) from clients.
- Allow **TCP 443** (or your TLS port) only to the reverse proxy that forwards to `127.0.0.1:9090`; avoid publishing 9090 directly to the Internet.

## Go module

Module path: `github.com/wesdod/mira-vpn/mira-vpn-wgmgr`. The control plane can depend on `github.com/wesdod/mira-vpn/mira-vpn-wgmgr/pkg/locationregistry` at a tagged version for shared location JSON types and loading.
