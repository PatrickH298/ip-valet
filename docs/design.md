# ip-valet API Design

Nov 24, 2026 · @Patrick · revised Nov 24, 2026: workers replace targets, client allow-lists removed, rules always enforced on existing entries, removals tracked per worker

## Overview

ip-valet keeps firewall allow-lists in sync with addresses that people register, each with an expiry. It is split into four parts so that new firewalls and new ways of registering can be added without touching the others.

| Component | Role | Talks to |
| --- | --- | --- |
| Database (Postgres) | Source of truth for all configuration, entries and state | API server only |
| API server (Go) | The only component with database access; validates, authorises, routes entries to workers, computes desired state and applied state | Database; accepts connections from clients and workers |
| Worker | Subscribes, through an admin, to the entries it should apply; applies them somewhere (a UniFi firewall is the first worker type) and reports back what it applied | API server, outbound only; whatever it applies entries to |
| Client | Submits entries on behalf of users (the registration website is the first client) | API server, outbound only |

```
  client ──────▶ API server ◀────── worker ──────▶ firewall
  (submits)          │          (fetches, reports)
                     ▼
                  Postgres
```

Every arrow is a connection its source opens, so neither workers nor clients accept inbound connections.

The API server has no notion of firewalls or other destinations. It knows workers: what each one subscribes to, which entries that routes to it, and which revision it last reported applying. Where and how a worker applies its list is up to the worker.

**Goals**

- Pluggable workers and clients that speak a published, versioned HTTP API.
- Firewalls stay correct when any one part is down: workers reconcile from full desired state and remove expired entries on their own.
- One running copy of each component today; nothing in the design prevents running two API servers or a standby worker process later.
- Everything a client asserts is bounded by limits the API enforces per realm, and no entry is ever left in place that breaks those limits.

**In scope:** the API server, its data model, rules, and the protocols workers and clients use.

**Deferred:** worker- and client-specific behaviour (decided per worker or client), and declarative admin configuration (a future version; Postgres is the only source of truth for now).

## Trust model and authentication

Every caller authenticates with an API key, and each key type can do one job. The API trusts a client's word about who a user is and which groups they belong to, within the realms its key is bound to. It does not verify that a submitted address belongs to the user; clients may submit addresses without detecting them (a chat bot, for example).

| Key type | Bound to | Can | Cannot |
| --- | --- | --- | --- |
| Client | One or more realms (required) | Submit, replace, list and delete entries in its realms; read their applied state | Act outside its realms; read desired state; manage configuration |
| Worker | Exactly one worker | Read that worker's desired state; receive signals; report status | Submit entries; read other workers' state; read or change configuration, including its own subscriptions |
| Admin | Global | Manage realms, clients, workers, subscriptions, keys and rules; list and delete any entry; read health and audit | Submit entries (entries always come through a client and its realm's rules) |

That is the whole of the enforcement: a client acts only inside its realms, everything it registers there is bounded by the realm's rules, and a worker sees only what an admin subscribed it to. There are no per-client user or group allow-lists.

**What limits a compromised component**

- A leaked client key can only act inside its realms, and only within the realms' rules.
- A leaked worker key exposes one worker's address list (prefixes and expiries, never who registered them) and nothing else. It cannot widen its own subscriptions.
- A compromised API can change desired state for every worker, so each worker keeps its own safety floor (see Worker protocol).
- Every change is audited with the client, the key id, and the realm, user and group the client asserted.

**Admin bootstrap.** Two ways to get the first admin key; both can be used together.

1. `create-admin-key`, run inside the API container, stores a hashed key in the database and prints it once. These keys can be listed and revoked through the API.
2. A key supplied at startup through `IPVALET_ADMIN_KEY`, `IPVALET_ADMIN_KEY_FILE` (a mounted secret; preferred, since environment variables are visible to `inspect` and `/proc`) or `IPVALET_ADMIN_KEY_HASH` (only the hash, so the host never holds the key). It is held in memory only, cannot be revoked through the API, and is rotated by changing the secret and restarting. Its audit actor is `admin:env`.

**Key format and handling**

- Format `ipv_<keyid>_<secret>`, with 256 bits of randomness in the secret.
- Only a SHA-256 hash of the secret is stored; the key is looked up by its id and compared in constant time.
- Sent as `Authorization: Bearer <key>`, over TLS only (terminated by the reverse proxy).
- Several active keys per client or worker, so rotation can overlap; optional expiry per key; revocation takes effect on the key's next request, and an open event stream ends within one heartbeat (20 s); `last_used_at` is recorded.
- **Brute-force protection.** Guessing a 256-bit secret is not feasible at any rate, so the protection is aimed at floods and scanning. A network (an IPv4 address, or an IPv6 /64, since one host can use a whole /64) that fails authentication 10 times in a minute has its requests refused unchecked, with 429 and `Retry-After`, until its budget refills; a refused request costs no database work. Successful requests never count, and a valid key used on the wrong route is not a failure. Failures are logged (a wrong secret for a real key id at warning level) and counted in metrics by reason.
- **The caller's address.** Behind the reverse proxy every connection comes from the proxy, so the server reads `X-Forwarded-For` only when the connection comes from a configured trusted proxy, taking the rightmost address that is not a trusted proxy. A client cannot pick its address by sending the header itself.
- **Event streams.** Each key may hold a few open event streams per API instance (4 by default), so a leaked key cannot multiply the work every change causes.
- **No caching.** Responses under `/v1` carry `Cache-Control: no-store`, since they can hold new keys and address lists.
- There are no rate limits on authenticated requests for now.

## Data model

All state lives in Postgres. A wildcard is stored as NULL and written `*` in the API; `*` is therefore not a valid realm, user or group name.

| Table | Key fields | Notes |
| --- | --- | --- |
| realms | name | Created by an admin. Creating one seeds its default rules (see Matching and rules). |
| clients | name, realms (one or more) | A client's scope is its realms. |
| api\_keys | key id, type (admin, client, worker), owner (client or worker), secret hash, expires\_at, revoked\_at, last\_used\_at | Environment-supplied admin keys are not stored here. |
| workers | name, label, families (IPv4, IPv6 or both), applied\_revision, applied\_generated\_at, subscriptions\_revision, last\_seen\_at, last\_error, last\_instance, last\_version | Registered by an admin. The label is the only part clients see. |
| subscriptions | worker, realm or `*`, user or `*`, group or `*` | Set by an admin for a worker. A specific user or group with realm `*` is allowed, with a warning. |
| entries | id, submission\_id, realm, user, group, prefix, expires\_at (NULL = unlimited), revision, client, key id, created\_at, updated\_at, deleted\_at, deleted\_by, deleted\_revision | Exactly one group per entry. Unique on (realm, user, group, prefix) among entries not deleted. |
| ip\_rules, ttl\_rules, prefix\_rules, cap\_rules | realm, user or `*`, group or `*`, position, plus the rule's own fields | Four separate ordered lists per realm (see Matching and rules). |
| worker\_rejections | worker, prefix, code, detail, revision | Replaced on each successful status report from that worker. |
| entry\_removals | entry, worker, revision | Which workers held an entry when it was deleted, or when they stopped matching it, and the revision each must reach to confirm removing it (see Applied state). |
| audit\_log | time, actor (key id or `admin:env`), client, action, realm, user, group, prefix, details | Kept 1 year by default. |
| revision | one global counter | Bumped by every change that can alter any worker's desired state (see Revisions). |

**Users and groups are realm-scoped.** A user is identified by (realm, user), so `authentik/patrick` and `discord/patrick` are different people. Group names are taken directly from the client's identity source (an authentik group name, for example); no translation layer exists.

**One group per entry.** A client sends a list of groups in one submission and the API creates one entry per group, sharing a `submission_id`. Each entry gets its own TTL, limits and status, and a client can delete a whole submission in one call.

## Matching and rules

Subscriptions and all four rule lists use the same (realm, user, group) selector, matched exactly and case-sensitively. Within one row all three fields must match, `*` matching anything; a worker applies an entry if any of its subscriptions match and the worker handles the entry's address family.

```sql
(s.realm    IS NULL OR s.realm    = e.realm) AND
(s.username IS NULL OR s.username = e.username) AND
(s.grp      IS NULL OR s.grp      = e.grp)
```

Rules differ from subscriptions in one way: a rule's realm is required. Each realm has four separate ordered lists, and an entry is decided by the **first matching rule** in each list, like a firewall. Admins reorder rules; a new rule is inserted above the realm's catch-all by default, and the admin API warns when a rule is shadowed by an earlier one.

| List | Rule fields | Effect of the first match | No rule matches | Seeded when the realm is created |
| --- | --- | --- | --- | --- |
| IP rules | prefix, ACCEPT or DENY | Decides whether the prefix may be registered (semantics below) | Rejected | DENY for each reserved range, then `ACCEPT 0.0.0.0/0` and `ACCEPT ::/0` |
| Prefix rules | shortest IPv4 prefix length, shortest IPv6 prefix length | Prefix must be no broader than the limit for its family | No limit | `realm/*/*`: IPv4 /32, IPv6 /64 |
| TTL rules | max TTL or unlimited | Submitted TTL must not exceed it | Accepted as submitted, including unlimited | `realm/*/*`: DEFAULT\_TTL (30 days unless configured) |
| Cap rules | limit | The user's active prefixes that first-match this same rule must not exceed the limit | No cap | None |

**IP rule semantics.** The first rule whose prefix overlaps the submitted prefix decides. DENY rejects. ACCEPT accepts only if the submitted prefix lies entirely inside the rule's prefix, and otherwise rejects. Matching on containment alone would be unsafe: with `DENY 10.0.0.0/8` above `ACCEPT 0.0.0.0/0`, a submitted `8.0.0.0/6` is not inside 10/8 and would skip the DENY, then be accepted with 10/8 inside it. Under overlap matching it hits the DENY and is rejected. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are converted to IPv4 before any matching, so they cannot bypass IPv4 rules.

**Cap counting.** A cap counts distinct prefixes, not entries, so one address registered in three groups counts once. For example, `discord/patrick/*` with limit 3 means Patrick has at most 3 addresses in the Discord realm; `authentik/*/guests` with limit 2 means each user has at most 2 addresses in `guests`. One rule's count never includes entries decided by another rule.

**Seeded reserved ranges.** These are editable per realm, so a setup that manages an internal list can allow private ranges.

- IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4
- IPv6: ::/8, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 3fff::/20, 5f00::/16, fc00::/7, fe80::/10, ff00::/8

**Changing rules and subscriptions.** No entry is ever left in place that fails a rule. Before an edit is saved, the admin API works out what it does to existing live entries (the impact) and requires confirmation; confirming saves the edit and its consequences together:

| The edit makes an entry… | What happens on confirm |
| --- | --- |
| fail an IP rule or a prefix rule | The entry is removed. |
| exceed a cap | For each user and cap rule, the most recently submitted prefixes are kept up to the limit; the entries holding the others are removed. |
| exceed a TTL rule (its remaining lifetime is longer than the max, or it is unlimited under a finite max) | The entry is shortened to now plus the max. |
| match no worker (a subscription, worker or family was removed) | Nothing: no rule fails, so the entry stays and reads `unrouted`. Re-adding a subscription routes it again. |

A dry run shows the same impact without saving. Every subscription edit bumps the worker's `subscriptions_revision`.

## Submission flow

A submission registers one prefix for one user in one or more groups, and is accepted or rejected as a whole.

```json
POST /v1/submissions
{
  "realm": "authentik",
  "user": "patrick",
  "groups": ["fwusers", "guests"],
  "prefix": "2001:db8:1234:5678::/64",
  "ttl": "86400s"
}
```

- `realm` may be omitted when the client's key is bound to exactly one realm.
- `user` and at least one group are required.
- `ttl` is required: a duration, or `"unlimited"`.

**Checks, in order.** Each group becomes one candidate entry, and every candidate must pass every check.

1. **Client scope.** The realm is one of the client's realms.
2. **Parse and normalise.** The prefix parses; an IPv4-mapped IPv6 address becomes IPv4; host bits are cleared (`203.0.113.7/24` becomes `203.0.113.0/24`) and the canonical form is returned.
3. **Routing.** Each group has at least one worker whose subscriptions match the entry and whose families include the prefix's family. Otherwise `no_subscriber`.
4. **IP rules.** The first overlapping rule must ACCEPT and contain the prefix.
5. **Prefix rules.** The prefix is no broader than the first matching rule allows.
6. **TTL rules.** The TTL does not exceed the first matching rule's max.
7. **Cap rules.** The user's distinct prefixes under the first matching cap rule, including this one, stay within its limit.

A failure returns 422 with one result per group, naming the check that failed and, where relevant, the limit (for example the max TTL allowed), so the client can retry or show the user.

**Re-submitting replaces.** If an entry already exists for the same (realm, user, group, prefix), it is updated in place rather than duplicated: all checks run again, the expiry becomes now plus the new TTL (so time never stacks, and a shorter TTL shortens it), it takes the new `submission_id` and a new revision, and keeps its id and audit trail. A submission can create some entries and replace others in the same call. An expired entry is revived the same way.

**Response.** The created or replaced entries with their ids, expiry, and applied state (usually `pending` at first).

## Worker protocol

A worker is registered by an admin, who sets its label, its address families and its subscriptions, and issues its keys. Workers always fetch their full desired state and reconcile; the event stream only tells them when to fetch. A dropped connection, a missed event or a restart therefore costs delay, never correctness.

1. The worker opens `GET /v1/worker/events`, a Server-Sent Events stream, and keeps it open.
2. It fetches `GET /v1/worker/desired-state`, applies it, and reports `POST /v1/worker/status`.
3. On each `changed` event, on reconnect, at `next_change_at`, and on a periodic timer as a fallback, it repeats step 2.

**Desired state**

```json
{
  "revision": 1842,
  "generated_at": "2026-11-24T17:00:00.123456Z",
  "next_change_at": "2026-11-24T18:05:00Z",
  "families": ["ipv4", "ipv6"],
  "entries": [
    { "prefix": "203.0.113.7/32", "expires_at": "2026-11-25T17:00:00Z" },
    { "prefix": "2001:db8:1234:5678::/64", "expires_at": null }
  ]
}
```

- One item per distinct prefix among the worker's matching, unexpired, undeleted entries, limited to its families. When several entries share a prefix, it carries the latest expiry (`null` if any is unlimited). The list says nothing about who registered a prefix.
- `next_change_at` is the earliest future expiry in the set, so the worker re-fetches the moment something expires rather than on its next timer.
- The response carries an `ETag` derived from its contents; a re-fetch with `If-None-Match` returns 304 when nothing changed for this worker. The 304 still carries the current revision and `generated_at` in headers, so the worker can report it is up to date.

**Events.** Each event carries the revision as its SSE id, and one is sent immediately on every connect. The server sends a comment line every 20 seconds so idle-connection timeouts in proxies do not cut the stream. Events may be sent more often than a worker's state actually changes; the ETag absorbs that.

**Status report**

```json
{ "instance": "unifi-1", "version": "0.3.0", "revision": 1842,
  "generated_at": "2026-11-24T17:00:00.123456Z",
  "rejected": [ { "prefix": "2001:db8::/32", "code": "prefix_too_broad", "detail": "…" } ] }
```

Or, on a transient failure: `{ "instance": "unifi-1", "version": "0.3.0", "revision": 1842, "error": "controller timeout: …" }`.

- `instance` names the process that sent the report (for example its host name). Several processes may share one worker's keys, such as a standby; `instance` tells them apart in health output.
- `generated_at` echoes the desired state that was applied. It is what confirms removal of expired entries.
- At most 200 rejections, each with a detail of at most 200 characters, so the largest valid report fits the default 64 KiB request body limit. A worker with more rejections than that reports an error instead.

On success the API raises the worker's `applied_revision` and `applied_generated_at` (never lowering them) and replaces the worker's rejections. A report with an older revision than the stored one is stale and only refreshes `last_seen_at`. On error it records `last_error` and leaves the applied position unchanged. Either way it updates `last_seen_at`.

**Rule for worker authors.** Report success only when everything except the listed rejections is in place; otherwise report an error. A worker type that applies entries one at a time must otherwise report an error. That keeps one revision number per worker meaningful.

**Expiry without the API.** Every item carries its expiry, so a worker that cannot reach the API removes expired prefixes from its cached state and the firewall on schedule. A database or API outage therefore never leaves expired access open.

**Safety floor.** Each worker validates desired state against its own configurable floor (by default: public addresses only, and a broadest-prefix limit) and rejects anything outside it with `address_not_allowed` or `prefix_too_broad`. A compromised API cannot push `0.0.0.0/0` or private ranges to a firewall whose worker forbids them.

Whether the cache persists across worker restarts, and all firewall-specific behaviour, are decided per worker type.

## Revisions and applied state

Applied state is computed from revisions when it is read, not stored per entry, so a worker applying 500 prefixes costs one write.

**What a revision is.** The revision is a single change counter for the whole system, not one per worker. Every change that can alter what any worker should hold takes the next number:

- an entry created, replaced, deleted or shortened;
- a subscription added or removed;
- a worker's families changed.

Rule edits take a number only through the removals and shortenings they cause. Each entry stores the number at which it was last written. Each worker stores the highest number it has reported applying (`applied_revision`) and the number of its last subscription or family change (`subscriptions_revision`).

For example: Patrick registers an address, which is change #42. The Home network worker fetches its desired state, which says "as of #42", applies it and reports "applied #42". Every entry routed to it with a number of 42 or lower is now known to be in place there; an entry written at #43 reads `pending` until the worker reports 43 or more.

The counter is a 64-bit integer. At 1,000 changes a second it would last about 292 million years (285,000 years before exceeding the 2^53 that JavaScript numbers represent exactly). Each change also sends a Postgres `NOTIFY`; every API instance `LISTEN`s and forwards an event to its connected workers and clients, so a second instance needs nothing extra.

**Per worker.** For each entry and each worker it matches:

| Condition | State on that worker |
| --- | --- |
| `applied_revision` is below the larger of the entry's revision and the worker's `subscriptions_revision` | `pending` |
| The worker has a rejection on record for the entry's prefix | `rejected` (with its code) |
| Otherwise | `active` |

Pending is checked first: a rejection on record belongs to the worker's last applied revision, so it counts only once the worker has caught up with the entry. The `subscriptions_revision` term matters: when a worker starts subscribing to a group, that group's existing entries have old revisions but have never been applied there, and would otherwise show as `active`.

**Overall state**, decided by the first condition that holds:

1. Deleted → `removed`; past its expiry → `expired`. Either reads `removing` until every worker that held it has confirmed (below).
2. No matching worker → `unrouted`. Submissions cannot create this; it appears only after a subscription or worker change.
3. Any worker `pending` → `pending`.
4. Every worker `rejected` → `rejected`.
5. Some workers `rejected` → `partial`.
6. Otherwise → `active`.

**Removal confirmation.** When an entry is deleted, or a worker stops matching it (a subscription deleted, a family dropped, its realm deleted), the server records in `entry_removals` which workers held it and the revision each must reach. A worker has confirmed the removal once its `applied_revision` reaches that revision, or, for an expired entry, once its `applied_generated_at` is past the expiry (expiry happens by time and bumps no revision). Confirmation therefore never depends on the worker still matching the entry. A live entry also lists a worker that stopped matching it as `removing` until that worker confirms. An entry can be confirmed removed while its prefix rightly stays on a firewall because another entry (another group) still covers it; clients that group entries by address should show that, rather than implying the address was blocked.

**What clients see.** Worker labels and states, and rejection codes, never details:

```json
{ "id": "…", "state": "partial", "expires_at": "…",
  "workers": [ { "label": "Home network", "state": "active" },
               { "label": "Game server",  "state": "rejected", "code": "prefix_too_broad" } ] }
```

Error text, `last_seen_at`, versions and other worker health are visible only to admin keys.

## API surface

All paths are under `/v1`, and the OpenAPI file in `spec/` is the contract other workers and clients build against. The protocol version (`/v1`) is separate from component release versions.

| Key | Method and path | Purpose |
| --- | --- | --- |
| Client | `POST /v1/submissions` | Create or replace entries (Submission flow) |
| Client | `DELETE /v1/submissions/{id}` | Delete every entry in a submission |
| Client | `GET /v1/entries` | List entries in the client's realms; filter by realm, user, group, prefix, state |
| Client | `GET /v1/entries/{id}` | One entry with its applied state |
| Client | `DELETE /v1/entries/{id}` | Delete one entry |
| Client | `GET /v1/events` | Optional SSE stream: `{id, state}` when an entry in the client's realms changes overall state |
| Worker | `GET /v1/worker/desired-state` | The worker's desired state |
| Worker | `GET /v1/worker/events` | SSE change signals |
| Worker | `POST /v1/worker/status` | Applied revision, rejections, or an error |
| Admin | `/v1/admin/realms`, `/clients`, `/workers`, `/workers/{id}/subscriptions`, `/subscriptions/{id}`, `/keys` | Create, read, update, delete; keys are shown once at creation |
| Admin | `/v1/admin/realms/{realm}/rules/{ip,prefix,ttl,cap}` | Rule lists, including reordering |
| Admin | `GET /v1/admin/entries`, `DELETE /v1/admin/entries/{id}` | Any entry, any realm |
| Admin | `GET /v1/admin/workers/{id}/health`, `GET /v1/admin/health`, `GET /v1/admin/audit` | Worker health and errors; audit log |
| None | `GET /healthz`, `GET /readyz`, `GET /metrics` | Liveness, readiness (database reachable), Prometheus metrics (separate port) |

A client sees, replaces and deletes everything in its realms, including entries another client submitted into a shared realm. Admin changes that affect existing entries return their impact and need `confirm=true` (see Matching and rules).

**Codes.** The spec owns a fixed catalog: codes can be added, but a code's meaning never changes.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `realm_not_allowed` | API | Realm not bound to the client's key |
| `invalid_prefix` | API | Prefix does not parse |
| `no_subscriber` | API | No worker applies this realm, user, group and family |
| `ip_denied` | API | An IP rule denied it, or no IP rule matched |
| `prefix_too_broad` | API or worker | Broader than a prefix rule or the worker's floor allows |
| `ttl_exceeded` | API | TTL above the matching rule's max |
| `cap_exceeded` | API | The user is at the matching cap rule's limit |
| `address_not_allowed` | Worker | Outside the worker's safety floor |
| `family_unsupported` | Worker | The worker cannot apply this address family |
| `capacity_exceeded` | Worker | The worker has no room for it (for example, a full firewall object) |
| `invalid` | Worker | Refused for another reason |

## Operations

The API server is written in Go: `net/http` (method-and-path routing, SSE), `net/netip` for prefix containment and overlap, and `pgx` for Postgres including `LISTEN`/`NOTIFY`. It ships as a static binary in a minimal image, behind a TLS-terminating reverse proxy.

| Area | Decision |
| --- | --- |
| Time | All expiry is computed from the database clock, never the API host's. |
| Migrations | Versioned SQL files (goose) run at startup inside a transaction, under a Postgres advisory lock so two instances cannot run them at once. |
| Retention | Expired and removed entries are purged after 90 days, the audit log after 1 year; both configurable. The purge job takes an advisory lock. |
| Health | `/healthz` reports the process is up; `/readyz` that the database is reachable and the `LISTEN` connection is up. |
| Metrics | Prometheus, on a separate port: submissions by result code, per-worker `last_seen_at`, per-worker revision lag (current revision minus `applied_revision`), connected workers. External monitoring alerts when a worker falls behind or goes quiet. |
| Configuration | Environment variables only, with built-in defaults (for example `IPVALET_DEFAULT_TTL=30d`); secrets also accept `_FILE` variants. |
| Existing data | Start empty; no import from `unifi-ip-valet`. |

**Ready for a second instance.** One API instance runs today. To keep a second one possible:

- No state that matters lives in memory. The failed-authentication throttle and the per-key stream count are kept per instance; they are protections, not records, so a second instance only gives an attacker a second budget.
- Change signals go through Postgres `NOTIFY` even with one instance.
- Background jobs (purge, migrations) take advisory locks.
- Several worker processes can share one worker's keys, and status reports name their `instance`, so a standby process with a lease can be added later without changing the protocol.

The database is a single point of failure by choice at this scale. Backups with point-in-time restore matter more than replication, and workers' offline expiry means an outage does not leave access open.

## Project

One public repository, `PatrickH298/ip-valet`, holds the API, the first-party workers and clients, and the spec, each versioned and released on its own.

```
ip-valet/
├── spec/openapi.yaml          # the contract: client, worker and admin APIs
├── docs/
│   ├── design.md              # this document
│   └── api-server-spec.md     # implementation spec for the API server
├── api/                       # Go module, own Dockerfile and version
│   ├── cmd/ipvalet-api/
│   ├── internal/
│   └── migrations/
├── workers/
│   └── unifi/                 # language chosen per worker
├── clients/
│   └── web/                   # language chosen per client
├── deploy/compose.example.yaml
└── .github/workflows/
```

- **One repo while the protocol settles.** An API change and the matching worker and client changes land in one pull request. A component moves to its own repo once it has its own contributors or release pace; third-party workers and clients live in their own repos from the start.
- **Versioning per component.** Semantic versions with path-prefixed tags (`api/v0.3.0`, `workers/unifi/v0.2.1`), which is also what Go requires for a module in a subdirectory. One image per component, for example `ghcr.io/patrickh298/ip-valet-api`, so a UniFi fix does not republish the API.
- **Images.** Built on every push to `main` and weekly.
- **CI.** A required status check that never runs blocks merging, so CI is one always-running workflow (`.github/workflows/ci.yml`) that detects which components changed, checks and tests those, checks DCO sign-offs on pull requests, and ends in one summary job, `CI summary`. Only that job is the required check in the `main` ruleset.
- **Licence.** AGPL-3.0. Workers and clients that talk to the API over HTTP are separate programs and are not bound by it; the README says so. Likely Go dependencies (MIT, BSD, Apache-2.0) are compatible.
- **Contributions.** Developer Certificate of Origin: every commit carries a `Signed-off-by` line, checked in CI.

## Decisions log

Questions that were open in the first draft, and how they were settled.

| Question | Decision |
| --- | --- |
| Deleting a realm that still has entries | Its entries are removed (they read `removing` until each worker that held them confirms); warning the admin is up to the admin dashboard. |
| A submitted prefix with host bits set (`203.0.113.7/24`) | Normalised to `203.0.113.0/24`; the canonical form is returned. |
| `DEFAULT_TTL` for seeded TTL rules | Set per deployment by environment variable (`IPVALET_DEFAULT_TTL`), default 30 days; used only when a realm is created. |
| Rate limits | None for now. Failed authentication is throttled per network instead (see Trust model and authentication). |
| Per-client user and group allow-lists | Removed. A client's scope is its realms; the realms' rules bound what it can register. |
| Existing entries that a rule change makes invalid | Always enforced on confirmation: removed or shortened. Caps keep the most recently submitted prefixes. |
| Who sets a worker's subscriptions | An admin. A worker cannot read or change its own subscriptions. |
| Target vs worker | The API knows only workers; where a worker applies its list is the worker's concern. |

**Deferred to each worker type**

- Whether the desired-state cache persists across restarts.
- Where firewall connection details and credentials live (worker secrets are the expected default; routing stays in the API).
- Safety floor defaults.
- UniFi: one worker holding both families across two lists, or one worker per family.
- UniFi: handling an empty list (the controller refuses one).

**Deferred to each client**

- Web client: authentik forward auth, the IPv4 and IPv6 detection hostnames, and widening a detected IPv6 address to /64.
- Which clients ship in the first release (the web client first; a Discord client later).
- Whether a client uses the events stream or polls for applied state.
