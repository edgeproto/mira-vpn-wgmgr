# VPS Deployment Runbook

This runbook covers onboarding one VPN POP (one VPS) for `mira-vpn-wgmgr` in real mode.

## Prerequisites

- A Linux VPS with root/sudo access
- Backend host public IP (for firewall allowlisting)
- DNS or static IP for the POP

## 1) Install system dependencies

Install:

- WireGuard kernel tooling (`wireguard`, `wg-quick`)
- Docker Engine
- Docker Compose plugin (`docker compose`)

## 2) Configure firewall

Open:

- UDP `51820` from anywhere (WireGuard client traffic)
- TCP `9090` from the backend host IP only (wgmgr control plane)

## 3) Generate server WireGuard keys

On the VPS:

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

Keep `privatekey` secret. You will place it in `wg0.conf`.

## 4) Bring up `wg0`

Create `/etc/wireguard/wg0.conf` with values for your POP, for example:

```ini
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = <contents of privatekey>
SaveConfig = true
```

Then start and persist it:

```bash
wg-quick up wg0
systemctl enable wg-quick@wg0
```

## 5) Deploy `mira-vpn-wgmgr`

Clone this repo on the VPS and create a `.env` file in the repo root:

```env
WGMGR_MODE=real
WGMGR_REAL_INTERFACE=wg0
WGMGR_REAL_OUTPUT_DIR=/var/lib/mira-wgmgr/peers
WGMGR_REAL_DRY_RUN=false
WGMGR_ADMIN_TOKEN=<long-random-token>
```

Start the service:

```bash
docker compose -f docker-compose.edge.yml up -d --build
```

## 6) Verify from backend host

From the backend host, verify authenticated health:

```bash
curl -H "Authorization: Bearer <token>" http://<vps-ip>:9090/health
```

Expected response: `ok`.

## 7) Register POP in backend

On the backend host:

1. Add/update the POP entry in `config/location-profiles.json`.
2. Set `WGMGR_ADMIN_TOKEN_<LOCATION_NAME>=<token>` in backend env.
3. Restart backend API container:

```bash
docker compose restart api
```

## Notes

- Use one unique token per POP.
- Restrict `:9090` access to backend host IP only.
- Keep WireGuard private keys and admin tokens out of git.
