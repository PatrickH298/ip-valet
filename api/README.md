# ip-valet API server

The ip-valet API server is one Go binary. It owns the Postgres database and
serves the client, worker and admin HTTP APIs. The contract that workers and
clients build against is [`spec/openapi.yaml`](../spec/openapi.yaml).

It listens for plain HTTP and is meant to sit behind a reverse proxy that
terminates TLS. All configuration comes from environment variables. The server
reads no config file.

## Commands

```
ipvalet-api [command]
```

| Command | Does |
| --- | --- |
| `serve` (default) | Runs migrations, then serves HTTP until SIGTERM or SIGINT |
| `migrate` | Runs migrations and exits |
| `create-admin-key --name <name> [--expires <duration>]` | Inserts an admin key and prints the full key once to stdout |
| `hash-key` | Reads a key on stdin and prints the value for `IPVALET_ADMIN_KEY_HASH` |
| `version` | Prints the version, commit and build date |

Migrations run under a Postgres session advisory lock, so several instances can
start at once.

### Getting the first admin key

You can get the first admin key in either of two ways, and you can use both:

1. Run `create-admin-key` inside the container:

   ```bash
   docker compose exec api ipvalet-api create-admin-key --name bootstrap
   ```

   The key is stored hashed. It can be listed and revoked through the API.

2. Supply a key at startup with `IPVALET_ADMIN_KEY_FILE` (a mounted secret,
   preferred), `IPVALET_ADMIN_KEY` or `IPVALET_ADMIN_KEY_HASH`. Any random key
   in the `ipv_<16 base32>_<52 base32>` format works, for example:

   ```bash
   KEY=$(printf 'ipv_%s_%s\n' \
     "$(head -c10 /dev/urandom | base32 | tr -d '=\n' | tr A-Z a-z)" \
     "$(head -c32 /dev/urandom | base32 -w0 | tr -d '=' | tr A-Z a-z)")
   ```

   To keep the key itself off the server host, give the server only its hash:

   ```bash
   echo "$KEY" | ipvalet-api hash-key   # prints <keyid>:<sha256 hex> for IPVALET_ADMIN_KEY_HASH
   ```

   This key is held in memory only. It cannot be listed or revoked through
   the API; to rotate it, change the secret and restart. Its audit actor is
   `admin:env`.

## Environment variables

Every variable has a built-in default. A variable marked *secret* also accepts
a `_FILE` variant (for example `IPVALET_DATABASE_URL_FILE`) naming a file whose
contents are the value, with one trailing newline trimmed. Setting both a
variable and its `_FILE` variant is a startup error. An invalid value stops the
server at startup, and the error message names the variable.

Durations use Go syntax (`90s`, `15m`, `36h`) plus a `d` suffix for whole days
(`30d`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DATABASE_URL` *(secret)* | required | Postgres connection string (Postgres 16 or newer) |
| `IPVALET_DB_MAX_CONNS` | `10` | Pool size; one more connection is held for `LISTEN` |
| `IPVALET_LISTEN_ADDR` | `:8080` | API listen address (plain HTTP) |
| `IPVALET_METRICS_ADDR` | `:9090` | Address for `/metrics`; empty disables metrics |
| `IPVALET_ADMIN_KEY` *(secret)* | unset | An admin key accepted in addition to database keys |
| `IPVALET_ADMIN_KEY_HASH` | unset | Alternative to `IPVALET_ADMIN_KEY`: `<keyid>:<hex sha256 of secret>` from `hash-key`. Setting both is an error. |
| `IPVALET_DEFAULT_TTL` | `30d` | Max TTL of the TTL rule seeded into each new realm |
| `IPVALET_DEFAULT_PREFIX_V4` | `32` | Shortest IPv4 prefix length in the seeded prefix rule |
| `IPVALET_DEFAULT_PREFIX_V6` | `64` | Shortest IPv6 prefix length in the seeded prefix rule |
| `IPVALET_DEFAULT_RATE_LIMIT` | `0` | Requests per minute per key for clients without their own limit; `0` = off |
| `IPVALET_RETENTION_ENTRIES` | `90d` | Purge deleted or expired entries this long after they ended |
| `IPVALET_RETENTION_AUDIT` | `365d` | Purge audit rows older than this |
| `IPVALET_PURGE_INTERVAL` | `1h` | How often the purge job runs |
| `IPVALET_SSE_HEARTBEAT` | `20s` | Interval between SSE `: ping` comments |
| `IPVALET_CLIENT_EVENTS_RECHECK` | `30s` | How often client event streams re-evaluate state (catches expiries) |
| `IPVALET_MAX_BODY_BYTES` | `65536` | Request body limit. The largest valid worker status report (200 rejections) is about 59 KB; below 61440 the server logs a warning at startup |
| `IPVALET_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

`IPVALET_DEFAULT_*` values are used only when a new realm is seeded. Changing
them later does not alter existing rules.

## Endpoints without authentication

- `GET /healthz` returns 200 `ok` whenever the process is serving.
- `GET /readyz` returns 200 when `SELECT 1` succeeds within 2 s and the
  `LISTEN` connection is up. Otherwise it returns 503.
- `GET /metrics` is served on `IPVALET_METRICS_ADDR` only, so the public
  proxy never exposes it.

Logs are JSON on stdout: one access line per request with the method, route
pattern, status, duration, actor and request id. Keys, the `Authorization`
header and request bodies are never logged. Every response carries an
`X-Request-Id` header.

## Container image

```bash
docker build -t ip-valet-api \
  --build-arg VERSION=0.1.0 \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  api/
```

The image is built from `gcr.io/distroless/static-debian12:nonroot`. It runs as
a non-root user, needs no writable filesystem and exposes 8080 (API) and 9090
(metrics).

## Development

You need Go 1.27 or newer, plus a Postgres 16 or newer that the tests can
create databases in.

```bash
cd api
go build ./...
go vet ./...
staticcheck ./...
```

```bash
IPVALET_TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

`IPVALET_TEST_DATABASE_URL` must be a `postgres://` URL for a role that can
create databases. Each test creates its own database and drops it afterwards.
If the variable is unset, the tests that need Postgres are skipped. A throwaway
server for local runs:

```bash
docker run --rm -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16
```

The acceptance tests in `internal/acceptance` cover every item in the
implementation spec's acceptance list. They also check every request the
server accepted, and every response it sent, against `spec/openapi.yaml`.
`internal/httpapi` checks that the spec and the route table list the same
operations. Set `IPVALET_TEST_LOG=1` to see server logs while tests run.

### Layout

```
api/
├── cmd/ipvalet-api/       subcommand dispatch
├── migrations/            goose SQL migrations, embedded
└── internal/
    ├── app/               wiring, serve/shutdown, subcommands
    ├── config/            environment parsing and validation
    ├── db/                pool, migrations, transactions, queries, LISTEN loop
    ├── auth/              key format, hashing, authentication, rate limits
    ├── rules/             names, TTLs, prefix normalisation, rule evaluation, seeding, warnings
    ├── state/             applied state, desired-state ETag
    ├── events/            SSE hub
    ├── httpapi/           handlers: client, worker, admin, health
    ├── metrics/           Prometheus metrics and the scrape-time collector
    ├── jobs/              purge
    ├── testutil/          test harness (disposable databases, instances)
    └── acceptance/        acceptance tests
```

## Licence

AGPL-3.0. Workers and clients that talk to the API over HTTP are separate
programs and are not bound by it.
