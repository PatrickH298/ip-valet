# ip-valet UniFi worker

Keeps UniFi **traffic matching lists** in line with the addresses registered in
ip-valet. Point UniFi firewall policies at those lists (Settings → Security →
Policies, source or destination → Traffic Matching List), and the worker keeps
their contents current: entries are added when registered and removed when
they are deleted or expire.

It is one Go binary, `ipvalet-unifi`. It talks to the ip-valet API as a worker
(see the [worker protocol](../../docs/design.md#worker-protocol)) and to the
UniFi Network integration API with an API key. It never changes firewall
policies, only list contents.

## How entries reach lists

The API sends the worker every entry its subscriptions route to it, with each
entry's realm, user and group. The worker's **rules** then decide which lists
each entry goes into. A rule takes entries by:

- **realm**: one realm, by name (required; no `*`)
- **user** and **group**: a name, or `*` for any
- **family**: `ipv4`, `ipv6` or `both`
- **addresses**: `public`, `private` or `both`

and names the IPv4 list and the IPv6 list that receive them. An entry goes into
the lists of **every** rule that takes it. Several rules may share a list.

Address kinds:

| Kind | Ranges |
| --- | --- |
| private | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (shared address space), fc00::/7 (unique local) |
| public | everything outside the reserved ranges below |
| never applied | loopback, link-local, documentation, benchmarking, multicast and the other reserved ranges the API's default IP rules deny, and any prefix that spans reserved space |

Before any rule, a **safety floor** refuses prefixes broader than
`IPVALET_UNIFI_MIN_PREFIX_V4` / `_V6` (default /24 and /48) and addresses that
are never applied. It guards UniFi even if the API sent something it should
not.

An entry that goes into no list is reported to the API as **rejected**, so it
shows as rejected (or partial) to users and admins, with a reason:

| Code | When |
| --- | --- |
| `no_matching_rule` | No rule takes the entry's realm, user and group |
| `family_unsupported` | A rule takes it, but not this address family |
| `address_not_allowed` | A rule takes it, but not this kind of address; or the address is never applied |
| `prefix_too_broad` | Broader than the safety floor |

When several entries share a prefix, the prefix counts as applied if any of them
went into a list. Keep the worker's subscriptions in the API about as narrow as
its rules, so entries it is not meant to apply are not routed to it at all.

### Rules in the environment

Each rule is one variable, `IPVALET_UNIFI_RULE_<NAME>`, whose value is
space-separated `key=value` pairs. `<NAME>` labels the rule in logs. Quote a
value that has spaces.

```bash
IPVALET_UNIFI_RULE_STAFF='realm=home group=staff ipv4_list=staff-v4 ipv6_list=staff-v6'
IPVALET_UNIFI_RULE_LAB='realm=home user="Zoë Smith" family=ipv4 addresses=private ipv4_list=lab-v4'
```

| Key | Default | Meaning |
| --- | --- | --- |
| `realm` | required | The realm, by name |
| `user` | `*` | A user name, or `*` |
| `group` | `*` | A group name, or `*` |
| `family` | `both` | `ipv4`, `ipv6` or `both` |
| `addresses` | `public` | `public`, `private` or `both` |
| `ipv4_list` | required when `family` takes IPv4 | The UniFi IPv4 list, by name or id |
| `ipv6_list` | required when `family` takes IPv6 | The UniFi IPv6 list, by name or id |

A list named by **name** is created if it does not exist (unless
`IPVALET_UNIFI_CREATE_LISTS=false`); one named by **id** must exist. A UniFi
list holds one family, so a list cannot be both a rule's `ipv4_list` and
another's `ipv6_list`.

> **The lists named in rules belong to the worker.** Every sync replaces their
> contents. Anything added to them by hand in the UniFi UI is removed on the next
> sync. Lists not named in any rule are never touched.

UniFi refuses an empty list, so a list with nothing in it holds a placeholder
instead: `192.0.2.1` (IPv4) or `100::1` (IPv6), addresses that are never routed.

## Syncing

The worker keeps the API's change-signal stream open and syncs on every signal,
at the next expiry, and every `IPVALET_UNIFI_SYNC_INTERVAL` (default 1 minute).
Each sync fetches the full desired state, works out every list's contents,
replaces each list that differs (only those), and reports to the API which
revision it applied and what it rejected. A failed list update is reported as
an error, so entries read `pending` rather than `active` until it succeeds.

**Without the API.** Desired state is cached in `IPVALET_UNIFI_DATA_DIR`
(default `/data`). While the API cannot be reached, the worker keeps syncing
from the cache, so expired entries still leave the lists on time, also across
restarts. It reports again once the API answers.

## Commands

```
ipvalet-unifi [command]
```

| Command | Does |
| --- | --- |
| `run` (default) | Keeps the lists in line until SIGTERM or SIGINT |
| `check` | Prints what a sync would do (the site, each list's changes, the rejections), changing nothing and reporting nothing |
| `version` | Prints the version |

## Setup

1. **Register the worker in ip-valet.** In the dashboard, under Workers, create
   a worker for the families you use, subscribe it to the realms (and users or
   groups) it should receive, and create a key for it.
2. **Create a UniFi API key.** On a local console: UniFi Network → Settings →
   Control Plane → Integrations. For the cloud connector: unifi.ui.com →
   account menu → API.
3. **Configure** the variables below, then run `ipvalet-unifi check` to see
   what it would do.
4. **Run it**, and point your UniFi firewall policies at the lists.

## Environment variables

A variable marked *secret* also accepts a `_FILE` variant naming a file that
holds the value, such as a Docker secret.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_UNIFI_API_URL` | required | The ip-valet API's main listener (client and worker API), for example `http://api:8080` |
| `IPVALET_UNIFI_API_KEY` *(secret)* | required | The worker's key |
| `IPVALET_UNIFI_CONTROLLER_URL` | required | The UniFi Network integration API: `https://<console>/proxy/network/integration`, or `https://api.ui.com/v1/connector/consoles/<console id>/proxy/network/integration` |
| `IPVALET_UNIFI_CONTROLLER_KEY` *(secret)* | required | A UniFi API key. It can reach the whole Network API, so give it to this worker only |
| `IPVALET_UNIFI_RULE_<NAME>` | at least one | A rule; see above |
| `IPVALET_UNIFI_SITE` | `Default` | The UniFi site, by name or id |
| `IPVALET_UNIFI_VERIFY_TLS` | `true` | Check the controller's TLS certificate. `false` accepts a local console's self-signed certificate; it is refused for the cloud connector |
| `IPVALET_UNIFI_CREATE_LISTS` | `true` | Create lists that rules name, by name, when they do not exist |
| `IPVALET_UNIFI_MIN_PREFIX_V4` | `24` | Broadest IPv4 prefix applied; broader ones are rejected |
| `IPVALET_UNIFI_MIN_PREFIX_V6` | `48` | Broadest IPv6 prefix applied; broader ones are rejected |
| `IPVALET_UNIFI_SYNC_INTERVAL` | `1m` | Sync at least this often, besides change signals and expiries |
| `IPVALET_UNIFI_TIMEOUT` | `15s` | Timeout for each request to the API or the controller |
| `IPVALET_UNIFI_DATA_DIR` | `/data` | Writable directory for the cached desired state; empty keeps it in memory only |
| `IPVALET_UNIFI_INSTANCE` | the host name | Name reported to the API, to tell processes sharing the worker's keys apart |
| `IPVALET_UNIFI_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

Logs are JSON on stdout. Every list change is logged with the prefixes added and
removed.

## Container image

```bash
docker build -t ip-valet-unifi workers/unifi/
```

Built from `gcr.io/distroless/static-debian12:nonroot`; runs as a non-root user.
Its only writable path is `/data`, a volume for the cache. The
[Compose example](../../deploy/README.md) runs it next to the API.

## Development

```bash
cd workers/unifi
go vet ./...
IPVALET_TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

The unit tests run against a fake UniFi controller (`internal/unifi/unifitest`)
that enforces what the real one does: the API key, at least one item per list,
and a single address sent without a prefix length. The end-to-end tests build
the API server from `../../api`, run it against Postgres, and drive the worker
against it. Without `IPVALET_TEST_DATABASE_URL` they are skipped; in CI they
fail instead.

## Licence

AGPL-3.0, like the rest of ip-valet.
