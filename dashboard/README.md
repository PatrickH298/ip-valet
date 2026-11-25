# ip-valet admin dashboard

A web interface for the ip-valet admin API: realms and their rules, workers
and their subscriptions, clients, keys, entries, the audit log and worker
health. It is one Go binary that calls the API server's admin listener with
its own admin key. It keeps no data of its own. The
[dashboard design](../docs/dashboard.md) explains how it works and why.

Pages are server-rendered HTML with no JavaScript. Anything that changes
existing entries shows what it will do and asks first: rule changes,
subscription and worker changes (through the API's impact check), and
deletions.

## Commands

```
ipvalet-dashboard [command]
```

| Command | Does |
| --- | --- |
| `serve` (default) | Serves the dashboard until SIGTERM or SIGINT |
| `hash-password <name>` | Reads a password on stdin and prints an htpasswd line (bcrypt) for the users file |
| `version` | Prints the version, commit and build date |

## Signing in

`IPVALET_DASHBOARD_AUTH` picks the method:

- `form` (default): a sign-in page, then a session cookie. Sessions are kept in
  memory, so a restart signs everyone out.
- `basic`: HTTP basic auth on every request. Browsers offer no sign-out.

Both read people from `IPVALET_DASHBOARD_USERS_FILE`, an htpasswd file with
bcrypt hashes. Make lines with `htpasswd -nB <name>` or `hash-password`. Every
person in the file is a full admin. The API's audit log records each change
with the person's name (`on_behalf_of`) next to the dashboard's key.

Failed sign-ins are throttled per client network (10 a minute by default).
Form posts from other sites are refused.

## Environment variables

A variable marked *secret* also accepts a `_FILE` variant naming a file that
holds the value. An invalid value stops the dashboard at startup, and the error
names the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DASHBOARD_API_URL` | required | The API server's admin listener, for example `http://api:8081` |
| `IPVALET_DASHBOARD_API_KEY` *(secret)* | required | The admin key the dashboard uses; give it its own, with an expiry |
| `IPVALET_DASHBOARD_USERS_FILE` | required | htpasswd file with bcrypt hashes; read at startup |
| `IPVALET_DASHBOARD_AUTH` | `form` | `form` or `basic` |
| `IPVALET_DASHBOARD_LISTEN_ADDR` | `:8090` | Listen address (plain HTTP, behind a proxy that terminates TLS) |
| `IPVALET_DASHBOARD_SECURE_COOKIES` | `true` | Mark cookies `Secure` (with the `__Host-` prefix). Needs HTTPS or `http://localhost`; `false` logs a warning |
| `IPVALET_DASHBOARD_SESSION_IDLE` | `30m` | Idle time that ends a session |
| `IPVALET_DASHBOARD_SESSION_MAX` | `12h` | Longest a session lasts |
| `IPVALET_DASHBOARD_LOGIN_FAILURES_PER_MINUTE` | `10` | Failed sign-ins allowed per IPv4 address or IPv6 /64 per minute; `0` = off |
| `IPVALET_DASHBOARD_TRUSTED_PROXIES` | unset | Comma-separated IPs or CIDRs of your reverse proxies; only their `X-Forwarded-For` is believed |
| `IPVALET_DASHBOARD_API_TIMEOUT` | `10s` | Timeout for each API call |
| `IPVALET_DASHBOARD_TIMEZONE` | `UTC` | IANA time zone for displayed times |
| `IPVALET_DASHBOARD_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_DASHBOARD_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

At startup the dashboard calls the API. A refused key, or a URL that points at
the public listener instead of the admin one, stops it. An API server that is
not up yet is only a warning; pages say so until it answers.

`GET /healthz` returns 200 `ok` without signing in. Logs are JSON on stdout:
one line per request with the path, status, duration, user and client address.
Passwords, cookies and keys are never logged.

## Container image

```bash
docker build -t ip-valet-dashboard \
  --build-arg VERSION=0.1.0 \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  dashboard/
```

The image is built from `gcr.io/distroless/static-debian12:nonroot`. It runs as
a non-root user, needs no writable filesystem and exposes 8090. The
[Compose example](../deploy/README.md) runs it next to the API server.

## Development

You need Go 1.27 or newer and, for the end-to-end tests, a Postgres 16 or newer
that the tests can create a database in. The tests build the API server from
`../api`, start it, and drive the dashboard against it.

```bash
cd dashboard
go vet ./...
IPVALET_TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

Without `IPVALET_TEST_DATABASE_URL` the end-to-end tests are skipped; in CI
they fail instead. Set `IPVALET_TEST_LOG=1` to see the API server's and the
dashboard's logs.

```
dashboard/
├── cmd/ipvalet-dashboard/   entry point
└── internal/
    ├── app/                 wiring, serve, commands
    ├── config/              environment parsing and validation
    ├── auth/                users file, sessions, form and basic sign-in, throttle
    ├── api/                 client for the admin API
    ├── web/                 handlers, templates, stylesheet
    └── e2e/                 end-to-end tests against a real API server
```

## Licence

AGPL-3.0, like the API server.
