# Deploying ip-valet

[`compose.example.yaml`](compose.example.yaml) runs the API server and its
Postgres database behind your existing reverse proxy, which terminates TLS.

| Port | Serves | Who should reach it |
| --- | --- | --- |
| 8080 | Client and worker API, `/healthz`, `/readyz` | Your reverse proxy only |
| 8081 | Admin API (`/v1/admin/*`), `/healthz`, `/readyz` | This host, or your LAN or VPN; never the internet |
| 9090 | Prometheus `/metrics` | Your monitoring, over an internal network |

## Setup

1. **Copy this directory** to the host and work inside it.

2. **Create the secrets.** Each one is a file under `secrets/`, mounted into
   the container that needs it:

   ```bash
   mkdir -p secrets
   openssl rand -hex 32 > secrets/postgres_password
   openssl rand -hex 32 > secrets/ipvalet_db_password
   printf 'postgres://ipvalet:%s@db:5432/ipvalet?sslmode=disable\n' "$(cat secrets/ipvalet_db_password)" > secrets/ipvalet_database_url
   ```

   The files are mounted with their host owner and mode. The API runs as user
   65532 and Postgres as user 999, so give each file to the user that reads it:

   ```bash
   sudo chown 65532 secrets/ipvalet_database_url
   ```

   ```bash
   sudo chown 999 secrets/postgres_password secrets/ipvalet_db_password
   ```

   ```bash
   sudo chmod 0400 secrets/*
   ```

3. **Tell the API where your proxy is.** Create `.env` next to the compose
   file with the proxy's address, or the subnet of the shared `proxy` network:

   ```bash
   echo 'IPVALET_TRUSTED_PROXIES=172.18.0.0/16' > .env
   ```

   The API believes `X-Forwarded-For` only from these addresses. Without the
   setting, Compose refuses to start.

4. **Connect the proxy network.** The compose file joins an external network
   named `proxy`. Create it, or rename it to the one your proxy already uses.

5. **Start it:**

   ```bash
   docker compose -f compose.example.yaml up -d
   ```

   On first start, `postgres-init/10-ipvalet.sh` creates the `ipvalet` role,
   which owns only the `ipvalet` database and is not a superuser. The API runs
   its migrations as that role.

6. **Create the first admin key** and keep it somewhere safe; it is shown once:

   ```bash
   docker compose -f compose.example.yaml exec api ipvalet-api create-admin-key --name bootstrap --expires 90d
   ```

7. **Route the public hostname** in your proxy to `api:8080`. Do not route
   8081 or 9090.

## Security notes

- **Container hardening.** The API runs as a non-root user with a read-only
  filesystem, no Linux capabilities and `no-new-privileges`. Postgres keeps
  its default capabilities, because its entrypoint starts as root to set up
  the data directory, but gets `no-new-privileges` and is on an internal
  network with no published port.
- **Database connection.** Inside one host's internal network,
  `sslmode=disable` is acceptable. If Postgres runs on another host, use TLS
  with certificate checks: `sslmode=verify-full&sslrootcert=/path/to/ca.crt`.
  Without `verify-full`, the connection can be intercepted.
- **Admin keys.** Give them an expiry (`--expires`, or `expires_at` in the
  API) and replace them before it passes. `GET /v1/admin/health` lists active
  keys expiring within 14 days or unused for 30 days.
- **Environment admin key.** If you bootstrap with an environment key, prefer
  `IPVALET_ADMIN_KEY_HASH`, so this host never holds the key, or
  `IPVALET_ADMIN_KEY_FILE` over plain `IPVALET_ADMIN_KEY`.
- **Backups.** Back up the `db-data` volume or run `pg_dump` regularly.
  Workers remove expired addresses on their own, so an outage never leaves
  expired access open, but the database holds every entry and key.
