# ip-valet admin dashboard

A web interface for the ip-valet admin API: realms and their rules, workers
and their subscriptions, clients, keys, entries, the audit log and worker
health. It is one Go binary that calls the API server's admin listener with
its own admin key. The only data it keeps is its login. The
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
| `reset-login` | Deletes the saved login, so the dashboard starts again from the default login; restart it afterwards |
| `version` | Prints the version, commit and build date |

## Signing in

The dashboard has one login. **On first boot it is form sign-in with user name
`admin` and password `admin`.** Signing in with it leads to the Account page,
and the dashboard cannot be used until you choose a new password there.

The Account page (your user name, top right) changes the user name, the
password and the sign-in method:

- **Sign-in page** (`form`, the default): a session cookie follows. Sessions
  are kept in memory, so a restart signs you out.
- **HTTP basic auth** (`basic`): the browser asks for the user name and
  password. Browsers offer no sign-out.

Every change needs the current password, and saving signs out every other
session. The login is saved as `login.json` (a bcrypt hash, never the password)
in `IPVALET_DASHBOARD_DATA_DIR`, which must be writable and should be a
persistent volume.

**Lost the password?** Run `reset-login` where the dashboard runs, then restart
it; the login is `admin` / `admin` again:

```bash
docker compose exec dashboard ipvalet-dashboard reset-login
```

```bash
docker compose restart dashboard
```

The API's audit log records each change made through the dashboard under the
login's user name (`on_behalf_of`), next to the dashboard's key. Failed sign-ins
are throttled per client network (10 a minute by default), and form posts from
other sites are refused. External sign-in with OpenID Connect is planned.

## Environment variables

Only `IPVALET_DASHBOARD_API_URL` and `IPVALET_DASHBOARD_API_KEY` are required. A
variable marked *secret* also accepts a `_FILE` variant naming a file that holds
the value, such as a Docker secret. An invalid value stops the dashboard at startup, and the error
names the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DASHBOARD_API_URL` | required | The API server's admin listener, for example `http://api:8081` |
| `IPVALET_DASHBOARD_API_KEY` *(secret)* | required | The admin key the dashboard uses; give it its own, with an expiry |
| `IPVALET_DASHBOARD_DATA_DIR` | `/data` | Writable directory for the login (`login.json`); keep it on a persistent volume |
| `IPVALET_DASHBOARD_LISTEN_ADDR` | `:8090` | Address the dashboard listens on (plain HTTP) |
| `IPVALET_DASHBOARD_SECURE_COOKIES` | `auto` | When cookies are marked `Secure` (a session cookie then takes the `__Host-` prefix): `auto` (when the browser came over HTTPS, directly or as `X-Forwarded-Proto` from a trusted proxy says), `true` (always; browsers then keep them only over HTTPS and on `http://localhost`) or `false` (never) |
| `IPVALET_DASHBOARD_SESSION_IDLE` | `30m` | Idle time that ends a session |
| `IPVALET_DASHBOARD_SESSION_MAX` | `12h` | Longest a session lasts |
| `IPVALET_DASHBOARD_LOGIN_FAILURES_PER_MINUTE` | `10` | Failed sign-ins allowed per IPv4 address or IPv6 /64 per minute; `0` = off |
| `IPVALET_DASHBOARD_TRUSTED_PROXIES` | `*` | Peers whose `X-Forwarded-For` and `X-Forwarded-Proto` are believed: `*` (every peer), `none`, or comma-separated IPs and CIDR prefixes |
| `IPVALET_DASHBOARD_API_TIMEOUT` | `10s` | Timeout for each API call |
| `IPVALET_DASHBOARD_TIMEZONE` | `UTC` | IANA time zone for displayed times |
| `IPVALET_DASHBOARD_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_DASHBOARD_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

At startup the dashboard calls the API. A refused key, or a URL that points at
the main listener instead of the admin one, stops it. An API server that is
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
a non-root user, uid and gid 65532, or as any other you give it (`docker run
--user 1000:1000`, or `user:` in Compose), and exposes 8090. Its only
writable path is `/data`, a volume any user can write to; the login file
there is readable only by the user that wrote it. A host folder mounted there
instead must belong to the dashboard's user. The
[Compose example](../deploy/README.md#running-as-another-user) runs it next to
the API server and covers changing the user.

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
    ├── auth/                the login and its store, sessions, form and basic sign-in, throttle
    ├── api/                 client for the admin API
    ├── web/                 handlers, templates, stylesheet
    └── e2e/                 end-to-end tests against a real API server
```

## Licence

AGPL-3.0, like the API server.
