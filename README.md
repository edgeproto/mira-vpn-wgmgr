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
- `WGMGR_ADMIN_TOKEN` — optional. When set, `POST /v1/peers` and `DELETE /v1/peers/{peerID}` require either `Authorization: Bearer <token>` or `X-Mira-Token: <token>`. `GET /health` stays unauthenticated for load balancers. Leave unset only on trusted networks (e.g. local dev).

## HTTP API

- `GET /health` — returns `200` and body `ok` (for load balancers).
- `POST /v1/peers` — JSON `{"userId":"...","location":"Finland"}`; `201` with peer metadata and WireGuard config.
- `DELETE /v1/peers/{peerID}` — `204` on success.

When `WGMGR_ADMIN_TOKEN` is set, mutating routes return `401` with `{"error":"unauthorized"}` if the token is missing or wrong.

## TLS and reverse proxy (recommended)

Run `wgmgr` bound to loopback only (default `ListenAndServe` on `0.0.0.0` — in production bind `127.0.0.1` via your process manager or firewall so only the proxy can reach port 9090). Terminate TLS on **Caddy** or **nginx** on the public host; forward HTTPS to `http://127.0.0.1:9090` with the same `Authorization` / `X-Mira-Token` headers the control plane sends.

**Caddy** (HTTPS on 443, Let’s Encrypt automatic if you use a real hostname):

```caddyfile
wg.example.com {
	reverse_proxy 127.0.0.1:9090
}
```

**nginx** (snippet):

```nginx
server {
	listen 443 ssl http2;
	server_name wg.example.com;
	ssl_certificate     /path/to/fullchain.pem;
	ssl_certificate_key /path/to/privkey.pem;
	location / {
		proxy_pass http://127.0.0.1:9090;
		proxy_http_version 1.1;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header Authorization $http_authorization;
		proxy_set_header X-Mira-Token $http_x_mira_token;
	}
}
```

Generate a long random secret for `WGMGR_ADMIN_TOKEN` (and the matching value in the control plane). Rotate per POP if you want blast-radius isolation.

**Security:** do not expose TCP 9090 on the public Internet without TLS and authentication. Prefer TLS at the edge proxy and keep this process on localhost.

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
