# ip-valet Admin Dashboard Design

The admin dashboard is a web interface for the admin API. People use it to
manage realms, rules, workers, subscriptions, clients and keys, to browse
entries and the audit log, and to see at a glance whether every worker is
keeping up. It adds no capability the admin API lacks: everything it does,
it does through that API.

## Shape

```
browser ──HTTP(S)──▶ [reverse proxy] ──▶ dashboard ──HTTP──▶ API admin listener (:8081)
                                         (:8090)             IPValet-On-Behalf-Of: <user>
```

A reverse proxy in front is optional; the dashboard serves plain HTTP itself.

- **A separate component.** `dashboard/` in the repository is its own Go
  module, binary (`ipvalet-dashboard`), image
  (`ghcr.io/patrickh298/ip-valet-dashboard`) and version (tags
  `dashboard/vX.Y.Z`), like the workers and clients. The API server stays an
  API.
- **The admin key stays on the server.** The dashboard holds one admin key and
  calls the admin API from the server side. Browsers never see the key; they
  hold only a session cookie, or send a password with basic auth.
- **Who did what.** Every API call carries `IPValet-On-Behalf-Of` with the
  signed-in user's name, so the audit log records the person (`on_behalf_of`)
  next to the dashboard's key (`actor`).
- **Almost no state of its own.** No database. The one thing it keeps is its
  login, in a small file in its data directory. Sessions live in memory, so a
  restart signs everyone out.
- **Server-rendered HTML.** Pages are Go `html/template`, forms are plain HTML
  forms, and v1 uses no JavaScript. That allows a strict Content Security
  Policy and needs no front-end build. htmx can be added later for progressive
  enhancement where it helps.

## Signing in

Without external sign-in, the dashboard has **one login**: a user name, a
password and a sign-in method. Every signed-in session is a full admin.

**First boot.** The login starts as the default:

| Method | User name | Password |
| --- | --- | --- |
| `form` | `admin` | `admin` |

Signing in with the default login leads straight to the Account page, and every
other page redirects there until a new password is chosen. The sign-in page
says that the default login is in use, and the server logs a warning at startup
for as long as it is.

**The Account page** changes the user name, the password and the sign-in
method. Every change needs the current password. A new password must be at
least 10 characters, at most 72 bytes (bcrypt's limit) and differ from the user
name. Saving signs out every other session; with form sign-in, the person who
saved gets a new session, and with basic auth their browser asks for the new
credentials.

| Method | How it works | Sign out |
| --- | --- | --- |
| `form` (default) | A sign-in page posts the user name and password. A session cookie follows. | A button; the session is deleted on the server. |
| `basic` | HTTP basic auth on every request. Successful checks are remembered in memory for 5 minutes, so bcrypt does not run on every page; a password change forgets them at once. | Not possible: browsers keep basic-auth credentials until they are closed. |

**Where the login is kept.** `login.json` in the data directory
(`IPVALET_DASHBOARD_DATA_DIR`, default `/data`): the method, the user name and a
bcrypt hash (cost 12) of the password, written atomically with mode 0600. The
directory must be writable, or the dashboard does not start. With no file, the
login is the default one; the default is not written to disk. A file that is
present but unreadable stops the dashboard rather than falling back to the
default.

**Lost password.** `ipvalet-dashboard reset-login` deletes the saved login.
After a restart the login is `admin` / `admin` again, and the first sign-in
asks for a new password.

**Sessions.** Each session has a random 256-bit id, kept in memory with the
user name and timestamps. It ends after 30 minutes idle or 12 hours in all
(both configurable), on sign-out, and when the login changes. A new id is
issued at every sign-in. The cookie is `HttpOnly` and `SameSite=Lax`.
`IPVALET_DASHBOARD_SECURE_COOKIES` decides when it is also `Secure`, with the
`__Host-` prefix: `auto` (the default) does so when the browser reached the
dashboard over HTTPS (TLS to the dashboard, `X-Forwarded-Proto: https` from a
trusted proxy, or an `https` origin on the form post), so plain HTTP and HTTPS
both work; `true` always does, and the sign-in page then explains when a
plain-HTTP page elsewhere than localhost cannot keep the cookie; `false` never
does. Over plain HTTP, the password and the cookie cross the network
unencrypted.

**External sign-in (later).** OpenID Connect, with a provider such as
authentik, replaces the local login: people are whoever the provider says, and
each is audited under their own name. Providers implement one interface:
identify the user on a request, challenge a request with no user (redirect to a
sign-in page, or 401 with `WWW-Authenticate`), and register their own routes
(login, callback, logout). The local login is one such provider; adding OIDC
means adding another and its settings, and pages do not change.

**Brute force.** Failed sign-ins, and wrong current passwords on the Account
page, are throttled per client network (an IPv4 address or IPv6 /64), 10 a
minute by default, as the API server does. Failures are not counted per user
name, since that would let anyone lock out the login. A wrong user name costs
the same bcrypt comparison as a wrong password. The client address comes from
`X-Forwarded-For` when the peer is a trusted proxy:
`IPVALET_DASHBOARD_TRUSTED_PROXIES` is `*` (every peer) by default, `none`, or a
list of addresses and prefixes.

## Browser security

- **Cross-site requests.** Every state-changing request (POST) goes through Go's
  `http.CrossOriginProtection`, which refuses cross-origin requests using
  `Sec-Fetch-Site` and `Origin`. It applies to both methods: basic-auth
  credentials, like cookies, are sent automatically.
- **Headers.** `Content-Security-Policy: default-src 'none'; style-src 'self';
  img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, and
  `Cache-Control: no-store` on every page, since pages hold entries, keys and
  audit data.
- **New keys.** A key's secret appears once, on the page that answers the
  create form. It is never put in a redirect, cookie or log.
- **Escaping.** Everything from the API is escaped by `html/template`.

## Pages

| Page | Shows | Actions |
| --- | --- | --- |
| Overview | API readiness, the current revision, each worker's lag, last report, last error, rejections and open streams; keys expiring soon or unused | |
| Realms | Realms; per realm, its four rule lists in order | Create and delete realms; add, edit, move and delete rules |
| Workers | Workers with health; per worker, its details, subscriptions, rejections and keys | Create, edit and delete workers; add and delete subscriptions; create and revoke worker keys |
| Clients | Clients and their realms; per client, its keys | Create, edit and delete clients; create and revoke client keys |
| Keys | Every key, filterable by kind | Create admin keys; revoke any key |
| Entries | Entries across realms, filterable by realm, user, group, prefix, state, client and worker, optionally including ended ones; per entry, its state on each worker and who added it | Add an entry for any realm, user and groups (through the realm's rules, with each refused group's reason); delete an entry |
| Audit | The audit log, filterable by time, actor, person, realm and action | |
| Account | The login | Change the user name, password and sign-in method |

Lists page with the API's cursors. Times are shown in
`IPVALET_DASHBOARD_TIMEZONE` (default UTC) and also as relative times.

**Confirming changes.** Nothing destructive happens in one click.

- **Impact-checked changes** (rules, subscription deletion, worker family
  changes and deletion): the dashboard sends the change without `confirm`. If
  the API answers 409 `confirmation_required`, the dashboard shows the impact
  (each affected entry and whether it will be removed or shortened) with a
  Confirm button, which repeats the change with `confirm=true`. Deletions are
  always previewed first with `dry_run=true`, even when they affect nothing.
- **Other deletions and revocations** (realms, clients, entries, keys) go
  through a confirmation page. For a realm, that page also counts the live
  entries the deletion will remove, which the design doc leaves to the
  dashboard.
- **Warnings** the API returns, such as `rule_shadowed`, are shown after the
  change.

## Configuration

Environment variables only, as for the API server. Secrets also accept a
`_FILE` variant naming a file that holds the value, such as a Docker secret.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DASHBOARD_LISTEN_ADDR` | `:8090` | Address the dashboard listens on (plain HTTP) |
| `IPVALET_DASHBOARD_API_URL` | required | The API server's admin listener, for example `http://api:8081` |
| `IPVALET_DASHBOARD_API_KEY` *(secret)* | required | The admin key the dashboard uses |
| `IPVALET_DASHBOARD_API_TIMEOUT` | `10s` | Timeout for each API call |
| `IPVALET_DASHBOARD_DATA_DIR` | `/data` | Writable directory that holds the login (`login.json`) |
| `IPVALET_DASHBOARD_SECURE_COOKIES` | `auto` | When cookies are `Secure`: `auto` (over HTTPS), `true` or `false` |
| `IPVALET_DASHBOARD_SESSION_IDLE` | `30m` | Idle time that ends a session |
| `IPVALET_DASHBOARD_SESSION_MAX` | `12h` | Longest a session lasts |
| `IPVALET_DASHBOARD_LOGIN_FAILURES_PER_MINUTE` | `10` | Failed sign-ins allowed per client network per minute; `0` = off |
| `IPVALET_DASHBOARD_TRUSTED_PROXIES` | `*` | Peers whose `X-Forwarded-For` and `X-Forwarded-Proto` are believed: `*`, `none`, or IPs and CIDR prefixes |
| `IPVALET_DASHBOARD_TIMEZONE` | `UTC` | IANA time zone for displayed times |
| `IPVALET_DASHBOARD_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_DASHBOARD_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

## Deployment

The dashboard is in the Compose example, on the same network as the API, with
its API key as an environment variable (or, commented out, a Docker secret), a
named volume at `/data` for its login, a read-only filesystem otherwise, and no
capabilities. Where its port is published, and whether a proxy or a
forward-auth layer such as authentik sits in front, is the deployer's choice.

The dashboard's admin key should be its own named key with an expiry, created
for it with `create-admin-key`, so that it can be revoked on its own and its
changes are recognisable in the audit log.

## Deferred

- OpenID Connect sign-in, with one audited identity per person.
- Roles, such as read-only users (only meaningful with external sign-in).
- Live updates (server-sent events from the API) and JavaScript enhancements.
