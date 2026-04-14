# SafeSwitch Node Deploy Guide

## Build and deploy

```bash
ssh root@<node-ip>
cd /root/safeswitch-router
git pull
export PATH=$PATH:/usr/local/go/bin
CGO_ENABLED=1 go build -o /root/ss-router ./cmd/ss-router 2>&1
systemctl stop ss-router
cp /root/ss-router /usr/local/bin/safeswitch-node
cp deploy/systemd/ss-router.service /etc/systemd/system/ss-router.service
```

## Required secrets — set manually on each node, never committed to repo

After copying the service file template, add these two lines to `/etc/systemd/system/ss-router.service` under `[Service]`:

```ini
Environment=SS_ROUTER_ANON_KEY=<supabase-anon-key>
Environment=SS_ROUTER_NODE_TOKEN=<node-token>
```

- **Anon key**: Supabase dashboard → Settings → API → `anon public` key
- **Node token**: stored in SQLite `tunnel_config` table, key `node_token` (e.g. `nt_53d1c4d7`)

## Required node identity files

The node needs these files in `SS_ROUTER_DATA_DIR` (`/root/ss-data`):

| File | Contents | How to set |
|---|---|---|
| `node_id` | UUID matching `nodes.id` in Supabase | `echo -n "<uuid>" > /root/ss-data/node_id` |
| `wireguard.key` | WireGuard private key | Generated on first enrollment or `wg genkey > /root/ss-data/wireguard.key` |

## Required SQLite seed values

```bash
sqlite3 /root/ss-data/router.db "
INSERT OR REPLACE INTO tunnel_config (key, value) VALUES ('node_id', '<uuid>');
INSERT OR REPLACE INTO tunnel_config (key, value) VALUES ('family_id', '<family-uuid>');
INSERT OR REPLACE INTO tunnel_config (key, value) VALUES ('node_token', '<node-token>');
"
```

## Start and verify

```bash
systemctl daemon-reload
systemctl start ss-router
journalctl -u ss-router -f
```

Within 30s you should see:
```
[controlsync] heartbeat ok node_id=<correct-uuid> ...
[controlsync] election heartbeat ok ... health=100 dns=true wg=true cloud=true state=active
[controlsync] tunnel stats: synced peers=N connected=N
```

## Key self-healing

`confirm_node_wg_key` fires on every heartbeat (every 30s). If the node key drifts (file recreated, SQLite wiped), it auto-corrects Supabase and bumps the bundle version so child devices re-fetch within one poll cycle.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `node_id` keeps regenerating | `SS_ROUTER_DATA_DIR` wrong | Check service file data dir points to where `node_id` file lives |
| `fetch-enforcement-sync` 403 | Node token missing or wrong | Add `SS_ROUTER_NODE_TOKEN` to service file |
| `confirm_node_wg_key` silent fail | Anon key missing | Add `SS_ROUTER_ANON_KEY` to service file |
| `wg0` peers wrong after restart | Stale bundle in SQLite | Force bundlesync via Supabase `command_ledger` INSERT |
| `status=203/EXEC` on start | Binary path wrong | Check `ExecStart` in service file matches actual binary location |
| `status=200/CHDIR` on start | `WorkingDirectory` doesn't exist | `mkdir -p <dir>` or update service file |
