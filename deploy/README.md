# Deploying ip-valet

[`compose.example.yaml`](compose.example.yaml) runs Postgres, the API server,
the admin dashboard and the UniFi worker with Docker Compose. Every setting is an environment
variable, set or listed (commented out, with its default and a definition) in
the file itself. Settings marked *secret* can come from files instead, such as
Docker secrets; the file shows that setup commented out.

| Port | Service | Serves |
| --- | --- | --- |
| 8080 | `api` | Client and worker API, `/healthz`, `/readyz` |
| 8081 | `api` | Admin API (`/v1/admin/*`), `/healthz`, `/readyz` |
| 9090 | `api` | Prometheus `/metrics` (not published in the example) |
| 8090 | `dashboard` | Admin dashboard |

The UniFi worker (`unifi`) serves nothing; it connects out to the API and to
your UniFi console.

The services share the project's default network. Other containers on that
network reach the API directly at `http://api:8080` and `http://api:8081`. Where
the ports are published, and whether a reverse proxy sits in front, is up to
you.

## First start

1. **Copy the example** and set a database password. It appears twice: in
   `POSTGRES_PASSWORD` and inside `IPVALET_DATABASE_URL`.

   ```bash
   cp compose.example.yaml compose.yaml
   ```

2. **Start Postgres and the API:**

   ```bash
   docker compose up -d db api
   ```

   The API creates its database if it does not exist (the role needs to be
   allowed to create databases, which the example's role is), then runs its
   migrations.

3. **Create an admin key for yourself.** It is printed once; keep it:

   ```bash
   docker compose exec api ipvalet-api create-admin-key --name bootstrap --expires 90d
   ```

   Alternatively, set `IPVALET_ADMIN_KEY` (or `IPVALET_ADMIN_KEY_HASH`) on the
   `api` service to a key you generate; see the [API README](../api/README.md).

4. **Give the dashboard its own key.** Create it, paste it into
   `IPVALET_DASHBOARD_API_KEY` in `compose.yaml`, and start the dashboard:

   ```bash
   docker compose exec api ipvalet-api create-admin-key --name dashboard --expires 365d
   ```

   ```bash
   docker compose up -d dashboard
   ```

5. **Sign in to the dashboard** at port 8090 with user name **`admin`** and
   password **`admin`**. The Account page opens; choose a new password there
   (the dashboard cannot be used until you do). The login is kept in the
   `dashboard-data` volume.

6. **Set up the UniFi worker** (skip this if you do not use UniFi):
   1. In the dashboard, create a realm and a client for your users, then under
      Workers create a worker, subscribe it to the realms (or users and groups)
      it should apply, and create a key on its page.
   2. In `compose.yaml`, set `IPVALET_UNIFI_API_KEY` to that key,
      `IPVALET_UNIFI_CONTROLLER_URL` and `IPVALET_UNIFI_CONTROLLER_KEY` to your
      console and a UniFi API key, and write the rules
      (`IPVALET_UNIFI_RULE_<NAME>`) that put entries into lists. The
      [worker's README](../workers/unifi/README.md) explains the rules.
   3. See what it would do, then start it:

      ```bash
      docker compose run --rm unifi check
      ```

      ```bash
      docker compose up -d unifi
      ```

   4. In UniFi, point your firewall policies at the lists. The worker creates
      lists that do not exist yet and replaces the contents of every list a rule
      names, but never changes policies.

## Using secrets instead of environment variables

Any setting marked *secret* in the example (the database URL, the admin key,
the dashboard's API key, the UniFi worker's two keys and the Postgres password)
can be read from a file by adding `_FILE` to its name. With Docker secrets:

1. Write each value to a file under `secrets/`:

   ```bash
   mkdir -p secrets && openssl rand -hex 32 > secrets/postgres_password
   ```

   ```bash
   printf 'postgres://ipvalet:%s@db:5432/ipvalet?sslmode=disable\n' "$(cat secrets/postgres_password)" > secrets/ipvalet_database_url
   ```

   ```bash
   docker compose exec -T api ipvalet-api create-admin-key --name dashboard --expires 365d > secrets/dashboard_api_key
   ```

2. Make each file readable by the user its service runs as: 65532 for the API,
   the dashboard and the UniFi worker, 999 for Postgres.

   ```bash
   sudo chown 65532 secrets/ipvalet_database_url secrets/dashboard_api_key && sudo chown 999 secrets/postgres_password && sudo chmod 0400 secrets/*
   ```

3. In `compose.yaml`, uncomment the `secrets:` block at the end, each service's
   `secrets:` line and its `*_FILE` variables, and remove the plain variables
   they replace (a variable and its `_FILE` form together are an error).

## Client addresses and proxies

The API and the dashboard record a client address in logs, and the API also
records one in the audit log and uses it for the failed-authentication
throttle. By default (`IPVALET_TRUSTED_PROXIES` and
`IPVALET_DASHBOARD_TRUSTED_PROXIES` unset, or `*`), every peer's
`X-Forwarded-For` header is believed, so a request can name any address. Set
them to your reverse proxy's address or subnet to believe the header only
from it, or to `none` to always use the connection's own address.

The dashboard marks its session cookie `Secure` when the browser reached it
over HTTPS, directly or through a proxy that sends `X-Forwarded-Proto`
(`IPVALET_DASHBOARD_SECURE_COOKIES=auto`, the default). Set it to `true` or
`false` to decide yourself.

## Operating

- **Lost dashboard password.** Reset the login to `admin` / `admin`, then sign
  in and choose a new one:

  ```bash
  docker compose exec dashboard ipvalet-dashboard reset-login && docker compose restart dashboard
  ```

- **Admin keys** can carry an expiry (`--expires`, or `expires_at` in the API).
  The dashboard's overview, and `GET /v1/admin/health`, list active keys
  expiring within 14 days or unused for 30 days.
- **Backups.** Back up the `db-data` volume, or run `pg_dump` regularly. It
  holds every entry and key. Workers remove expired addresses on their own, so
  a database outage does not leave expired access in place.
- **Container settings.** The example runs the API, the dashboard and the
  UniFi worker with a read-only filesystem (the dashboard and the worker write
  only to their `/data` volumes), no Linux capabilities and
  `no-new-privileges`. The images run as uid 65532.

## Optional: a database role with fewer rights

The example's role is a superuser of its own Postgres container. To have the
API connect as a role that owns only its database, create the role and the
database as a superuser, then point `IPVALET_DATABASE_URL` at that role:

```bash
docker compose exec db psql -U ipvalet -d postgres -c "CREATE ROLE ipvalet_app LOGIN PASSWORD 'another-password'" -c "CREATE DATABASE ipvalet_app OWNER ipvalet_app"
```

The API then finds its database already there and needs no further rights.
Alternatively, `ALTER ROLE ipvalet_app CREATEDB` lets the API create it.

When Postgres runs on another host, connect with TLS and certificate checks:
`sslmode=verify-full&sslrootcert=/path/to/ca.crt` in the URL.
