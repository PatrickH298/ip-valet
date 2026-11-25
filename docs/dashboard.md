# ip-valet Admin Dashboard Design

The admin dashboard is a web interface for the admin API. People use it to
manage realms, rules, workers, subscriptions, clients and keys, to browse
entries and the audit log, and to see at a glance whether every worker is
keeping up. It adds no capability the admin API lacks: everything it does,
it does through that API.

## Shape

```
browser ──HTTPS──▶ reverse proxy ──▶ dashboard ──HTTP──▶ API admin listener (:8081)
                                     (:8090)             IPValet-On-Behalf-Of: <user>
```

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
- **No state of its own.** No database. Users come from a file, and sessions
  live in memory, so a restart signs everyone out.
- **Server-rendered HTML.** Pages are Go `html/template`, forms are plain HTML
  forms, and v1 uses no JavaScript. That allows a strict Content Security
  Policy and needs no front-end build. htmx can be added later for progressive
  enhancement where it helps.

## Signing in

Authentication is pluggable. One method is configured at a time
(`IPVALET_DASHBOARD_AUTH`); every method yields the same identity, a user name,
and every signed-in user is a full admin. Roles, such as read-only users, are
deferred.

| Method | How it works | Sign out |
| --- | --- | --- |
| `form` (default) | A login page posts a user name and password. A session cookie follows. | A button; the session is deleted on the server. |
| `basic` | HTTP basic auth on every request. Successful checks are remembered in memory for 5 minutes, so bcrypt does not run on every page. | Not possible: browsers keep basic-auth credentials until they are closed. |
| `oidc` (later) | Redirect to an OpenID Connect provider such as authentik; the callback creates a session as `form` does. Optionally, only members of a configured group are let in. | As `form`, and optionally the provider's own logout. |

**Users file.** `form` and `basic` read users from `IPVALET_DASHBOARD_USERS_FILE`,
in htpasswd format with bcrypt hashes (`name:$2y$...`), one per line. Generate a
line with `htpasswd -nB <name>` or `ipvalet-dashboard hash-password <name>`.
Other hash types are refused at startup. The file is read at startup; restart to
apply changes.

**Sessions.** Each session has a random 256-bit id, kept in memory with the
user name and timestamps. It ends after 30 minutes idle or 12 hours in all
(both configurable), and on sign-out. A new id is issued at every sign-in. The
cookie is `HttpOnly`, `SameSite=Lax` and, by default, `Secure` with the
`__Host-` prefix. Serving over plain HTTP needs
`IPVALET_DASHBOARD_SECURE_COOKIES=false`; the server then logs a warning,
because passwords and the cookie cross the network in the clear.

**Room for OIDC.** Providers implement one interface: identify the user on a
request, challenge a request with no user (redirect to the login page, or 401
with `WWW-Authenticate`), and register their own routes (login, callback,
logout). `form` and `oidc` share the session store and sign-out. Adding `oidc`
means adding a provider and its settings; pages and handlers do not change.

**Brute force.** Failed sign-ins are throttled per client network (an IPv4
address or IPv6 /64), 10 a minute by default, as the API server does. Failures
are not counted per user name, since that would let anyone lock out a known
user. An unknown user name still costs one bcrypt comparison, so response
timing does not reveal which names exist. Behind a reverse proxy, the client
address comes from `X-Forwarded-For` only when the proxy is listed in
`IPVALET_DASHBOARD_TRUSTED_PROXIES`.

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
| Entries | Entries across realms, filterable by realm, user, group, prefix, state, client and worker, optionally including ended ones; per entry, its state on each worker | Delete an entry |
| Audit | The audit log, filterable by time, actor, person, realm and action | |

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
`_FILE` variant.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DASHBOARD_LISTEN_ADDR` | `:8090` | Listen address (plain HTTP, behind the proxy) |
| `IPVALET_DASHBOARD_API_URL` | required | The API server's admin listener, for example `http://api:8081` |
| `IPVALET_DASHBOARD_API_KEY` *(secret)* | required | The admin key the dashboard uses |
| `IPVALET_DASHBOARD_API_TIMEOUT` | `10s` | Timeout for each API call |
| `IPVALET_DASHBOARD_AUTH` | `form` | `form` or `basic` (`oidc` later) |
| `IPVALET_DASHBOARD_USERS_FILE` | required for `form` and `basic` | htpasswd file with bcrypt hashes |
| `IPVALET_DASHBOARD_SECURE_COOKIES` | `true` | Mark the session cookie `Secure` (needs HTTPS in front) |
| `IPVALET_DASHBOARD_SESSION_IDLE` | `30m` | Idle time that ends a session |
| `IPVALET_DASHBOARD_SESSION_MAX` | `12h` | Longest a session lasts |
| `IPVALET_DASHBOARD_LOGIN_FAILURES_PER_MINUTE` | `10` | Failed sign-ins allowed per client network per minute; `0` = off |
| `IPVALET_DASHBOARD_TRUSTED_PROXIES` | unset | Proxies whose `X-Forwarded-For` is believed |
| `IPVALET_DASHBOARD_TIMEZONE` | `UTC` | IANA time zone for displayed times |
| `IPVALET_DASHBOARD_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_DASHBOARD_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

## Deployment

The dashboard joins the Compose example: on the internal network to reach the
API's admin listener, with the API key and users file mounted as secrets, a
read-only filesystem and no capabilities. Its port is bound to the host only,
like the admin port. Expose it through the reverse proxy over HTTPS when it is
needed from elsewhere; authentik or another forward-auth layer can sit in front
as an extra gate.

The dashboard's admin key should be its own named key with an expiry, created
for it with `create-admin-key`, so that it can be revoked on its own and its
changes are recognisable in the audit log.

## Deferred

- OpenID Connect sign-in.
- Roles, such as read-only users.
- Live updates (server-sent events from the API) and JavaScript enhancements.
- Changing the users file without a restart.
