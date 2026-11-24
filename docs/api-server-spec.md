# ip-valet API Server: Implementation Spec

Nov 24, 2026 · @Patrick · revised Nov 24, 2026 to match the built server: workers replace targets, client allow-lists removed, the impact check always enforces, removals are tracked per worker, smaller status reports

Build instructions for the API server described in [the design doc](design.md). Where the two differ, the design doc's decisions win; this spec fills in the detail needed to build it.

## Scope and deliverables

Build the ip-valet API server: one Go binary that owns the Postgres database and serves the client, worker and admin HTTP APIs. Worker and client programs are out of scope; build only the server side of their protocols.

**Deliverables, under `api/` and `spec/` in `PatrickH298/ip-valet`**

1. The Go module `github.com/PatrickH298/ip-valet/api`, with the commands in Stack, layout and commands.
2. A database migration reproducing the schema in this spec.
3. `spec/openapi.yaml` (OpenAPI 3.1) describing every endpoint, request and response in this spec. It is the contract third-party workers and clients build against, so it must match the server exactly.
4. A `Dockerfile` producing a minimal, non-root image.
5. Tests covering every item in Acceptance tests, runnable with `go test ./...` against a disposable Postgres named by `IPVALET_TEST_DATABASE_URL`.
6. A `README.md` in `api/` listing the environment variables and commands.

**Definition of done**

- Every acceptance test passes.
- `go vet ./...` and `staticcheck ./...` are clean.
- The OpenAPI file validates, every route in the server appears in it and every operation in it is served, and every request the server accepts and every response it sends during the acceptance tests validates against it.
- Nothing in the server reads a config file; all configuration comes from environment variables.
- No item in Implementation defaults has been changed without the owner's agreement.

**How to read this spec.** Terms (realm, worker, subscription, entry, submission, revision) are defined in the design doc. Anything this spec had to decide that the design doc does not state is listed under Implementation defaults at the end.

## Stack, layout and commands

| Concern | Use |
| --- | --- |
| Language | Go, latest stable release (1.27); standard library first |
| HTTP | `net/http` with method-and-path patterns (`mux.HandleFunc("POST /v1/submissions", …)`); no web framework |
| Prefixes | `net/netip` (`Prefix`, `Addr`) for parsing, containment and overlap |
| Postgres | `github.com/jackc/pgx/v5` and `pgxpool`; a dedicated connection for `LISTEN` |
| Migrations | `github.com/pressly/goose/v3`, SQL migrations embedded with `embed` |
| Metrics | `github.com/prometheus/client_golang` |
| Rate limiting | `golang.org/x/time/rate` |
| Logging | `log/slog`, JSON to stdout |
| Postgres server | 16 or newer (needs `UNIQUE NULLS NOT DISTINCT` and `gen_random_uuid()`) |
| Test only | `github.com/pb33f/libopenapi-validator` to check requests and responses against `spec/openapi.yaml` |

Add other dependencies only when the standard library cannot do the job reasonably; each must be MIT, BSD, Apache-2.0 or similarly AGPL-compatible.

```
api/
├── cmd/ipvalet-api/main.go     # subcommand dispatch
├── migrations/                 # *.sql, embedded
├── internal/
│   ├── app/                    # wiring, serve and shutdown, subcommands
│   ├── config/                 # environment parsing and validation
│   ├── db/                     # pool, migrations, queries, transactions, LISTEN loop
│   ├── auth/                   # key format, hashing, authentication, rate limits
│   ├── rules/                  # names, TTLs, prefixes, rule evaluation, seeding, warnings
│   ├── state/                  # applied state, desired-state ETag
│   ├── events/                 # SSE hub
│   ├── httpapi/                # handlers: client, worker, admin, health
│   ├── metrics/                # Prometheus metrics and scrape-time collector
│   ├── jobs/                   # purge
│   ├── testutil/               # test harness: disposable databases and instances
│   └── acceptance/             # acceptance tests
├── Dockerfile
├── go.mod
└── README.md
```

**Subcommands of `ipvalet-api`**

| Command | Does |
| --- | --- |
| `serve` (default) | Runs migrations, then serves HTTP until SIGTERM or SIGINT |
| `migrate` | Runs migrations and exits |
| `create-admin-key --name <name> [--expires <duration>]` | Inserts an admin key and prints the full key once to stdout |
| `hash-key` | Reads a key on stdin and prints the value for `IPVALET_ADMIN_KEY_HASH` |
| `version` | Prints the version, commit and build date (set with `-ldflags`) |

**Container image.** Multi-stage build, `CGO_ENABLED=0`, final stage `gcr.io/distroless/static-debian12:nonroot`, entrypoint `ipvalet-api`, exposing the API and metrics ports. The image runs as a non-root user and needs no writable filesystem.

## Configuration

All configuration comes from environment variables, each with a built-in default; there is no config file. Every variable marked *secret* also accepts a `_FILE` variant (for example `IPVALET_DATABASE_URL_FILE`) naming a file whose contents, with one trailing newline trimmed, are the value. Setting both a variable and its `_FILE` variant is a startup error. Invalid values stop the server at startup with a message naming the variable.

Durations use Go syntax (`90s`, `15m`, `36h`) plus a `d` suffix for whole days (`30d`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `IPVALET_DATABASE_URL` *(secret)* | required | Postgres connection string |
| `IPVALET_DB_MAX_CONNS` | `10` | Pool size (one more connection is held for `LISTEN`) |
| `IPVALET_LISTEN_ADDR` | `:8080` | API listen address, plain HTTP behind a TLS-terminating proxy |
| `IPVALET_METRICS_ADDR` | `:9090` | Address for `/metrics`; empty disables metrics |
| `IPVALET_ADMIN_KEY` *(secret)* | unset | An admin key accepted in addition to database keys |
| `IPVALET_ADMIN_KEY_HASH` | unset | Alternative to `IPVALET_ADMIN_KEY`: `<keyid>:<hex sha256 of secret>`, as printed by `hash-key`. Setting both is an error. |
| `IPVALET_DEFAULT_TTL` | `30d` | Max TTL of the TTL rule seeded into each new realm |
| `IPVALET_DEFAULT_PREFIX_V4` | `32` | Shortest IPv4 prefix length in the seeded prefix rule |
| `IPVALET_DEFAULT_PREFIX_V6` | `64` | Shortest IPv6 prefix length in the seeded prefix rule |
| `IPVALET_DEFAULT_RATE_LIMIT` | `0` | Requests per minute per key for clients without their own limit; `0` = off |
| `IPVALET_RETENTION_ENTRIES` | `90d` | Purge deleted or expired entries this long after they ended |
| `IPVALET_RETENTION_AUDIT` | `365d` | Purge audit rows older than this |
| `IPVALET_PURGE_INTERVAL` | `1h` | How often the purge job runs |
| `IPVALET_SSE_HEARTBEAT` | `20s` | Interval between SSE comment lines |
| `IPVALET_CLIENT_EVENTS_RECHECK` | `30s` | How often client event streams re-evaluate state (catches expiries) |
| `IPVALET_MAX_BODY_BYTES` | `65536` | Request body limit. Below 61440 (what the largest valid status report needs) the server logs a warning at startup. |
| `IPVALET_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `IPVALET_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

`IPVALET_DEFAULT_*` values are used only when seeding a new realm; changing them later does not alter existing rules.

## Database schema

The migration creates the schema below. A wildcard (`*` in the API) is stored as NULL. Prefixes use Postgres `cidr`, which rejects host bits, so values are normalised in Go before they are written.

```sql
CREATE DOMAIN realm_name AS text
  CHECK (VALUE ~ '^[a-z0-9][a-z0-9._-]{0,62}$');
CREATE DOMAIN ident_name AS text          -- users and groups
  CHECK (VALUE <> '*' AND char_length(VALUE) BETWEEN 1 AND 256
         AND VALUE !~ '[[:cntrl:]]');

-- One row. Every revision-bumping write locks and increments it (see Revisions).
CREATE TABLE revision_counter (
  id    boolean PRIMARY KEY DEFAULT true CHECK (id),
  value bigint  NOT NULL DEFAULT 0
);
INSERT INTO revision_counter DEFAULT VALUES;

CREATE TABLE realms (
  name       realm_name PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE clients (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                  text NOT NULL UNIQUE,
  rate_limit_per_minute integer CHECK (rate_limit_per_minute >= 0),
                                        -- NULL = IPVALET_DEFAULT_RATE_LIMIT; 0 = off
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE client_realms (
  client_id uuid       NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  realm     realm_name NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  PRIMARY KEY (client_id, realm)
);

CREATE TABLE workers (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                   text NOT NULL UNIQUE,   -- admin handle
  label                  text NOT NULL,          -- the only field clients see
  ipv4                   boolean NOT NULL,
  ipv6                   boolean NOT NULL,
  applied_revision       bigint NOT NULL DEFAULT 0,
  applied_generated_at   timestamptz,
  subscriptions_revision bigint NOT NULL DEFAULT 0,
  last_seen_at           timestamptz,
  last_error             text,
  last_error_at          timestamptz,
  last_instance          text,                   -- from the last status report
  last_version           text,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  CHECK (ipv4 OR ipv6)
);

CREATE TABLE subscriptions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_id  uuid NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  realm      realm_name REFERENCES realms(name) ON DELETE CASCADE,  -- NULL = *
  username   ident_name,                                            -- NULL = *
  grp        ident_name,                                            -- NULL = *
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (worker_id, realm, username, grp)
);

CREATE TABLE api_keys (
  id           text PRIMARY KEY CHECK (id ~ '^[a-z2-7]{16}$'),
  kind         text NOT NULL CHECK (kind IN ('admin', 'client', 'worker')),
  client_id    uuid REFERENCES clients(id) ON DELETE CASCADE,
  worker_id    uuid REFERENCES workers(id) ON DELETE CASCADE,
  name         text NOT NULL,
  secret_hash  bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  CHECK ((kind = 'admin'  AND client_id IS NULL     AND worker_id IS NULL)
      OR (kind = 'client' AND client_id IS NOT NULL AND worker_id IS NULL)
      OR (kind = 'worker' AND worker_id IS NOT NULL AND client_id IS NULL))
);

CREATE TABLE entries (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id    uuid NOT NULL,
  realm            realm_name NOT NULL,  -- no FK: rows outlive a deleted realm until purged
  username         ident_name NOT NULL,
  grp              ident_name NOT NULL,
  prefix           cidr NOT NULL,
  expires_at       timestamptz,          -- NULL = unlimited
  revision         bigint NOT NULL,
  client_id        uuid REFERENCES clients(id) ON DELETE SET NULL,
  key_id           text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),  -- last submitted or replaced
  deleted_at       timestamptz,
  deleted_by       text,
  deleted_revision bigint,
  CHECK ((deleted_at IS NULL) = (deleted_revision IS NULL))
);
-- Expired rows are not deleted, so re-submitting one revives it in place.
CREATE UNIQUE INDEX entries_one_live ON entries (realm, username, grp, prefix)
  WHERE deleted_at IS NULL;
CREATE INDEX entries_live_by_user ON entries (realm, username) WHERE deleted_at IS NULL;
CREATE INDEX entries_by_submission ON entries (submission_id);

-- The four rule lists share these columns; position is unique per realm and list.
CREATE TABLE ip_rules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  realm       realm_name NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  username    ident_name,   -- NULL = *
  grp         ident_name,   -- NULL = *
  position    integer NOT NULL,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  prefix      cidr NOT NULL,
  action      text NOT NULL CHECK (action IN ('accept', 'deny')),
  UNIQUE (realm, position) DEFERRABLE INITIALLY DEFERRED
);
-- prefix_rules: same shared columns, plus
--   min_len_v4 smallint CHECK (min_len_v4 BETWEEN 0 AND 32),   -- NULL = no IPv4 limit
--   min_len_v6 smallint CHECK (min_len_v6 BETWEEN 0 AND 128),  -- NULL = no IPv6 limit
-- ttl_rules: same shared columns, plus
--   max_ttl_seconds bigint CHECK (max_ttl_seconds > 0),        -- NULL = unlimited
-- cap_rules: same shared columns, plus
--   max_prefixes integer NOT NULL CHECK (max_prefixes >= 0)

CREATE TABLE worker_rejections (
  worker_id uuid NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  prefix    cidr NOT NULL,
  code      text NOT NULL,
  detail    text,
  revision  bigint NOT NULL,
  PRIMARY KEY (worker_id, prefix)
);

-- Which workers held an entry when it was deleted, or when they stopped
-- matching it, and the revision each must reach to confirm removing it.
CREATE TABLE entry_removals (
  entry_id  uuid   NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  worker_id uuid   NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  revision  bigint NOT NULL,
  PRIMARY KEY (entry_id, worker_id)
);
CREATE INDEX entry_removals_worker ON entry_removals (worker_id);

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text NOT NULL,   -- key id, 'admin:env' or 'system'
  client_id   uuid,
  action      text NOT NULL,   -- e.g. entry.create, entry.replace, entry.shorten, rule.update
  object_type text NOT NULL,
  object_id   text,
  realm       text,
  username    text,
  grp         text,
  prefix      cidr,
  details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at);
```

The migration writes the three abbreviated rule tables out in full. Rule positions are dense integers starting at 1; a reorder rewrites them inside one transaction, which the deferred unique constraint allows.

## Authentication

Every `/v1` request carries `Authorization: Bearer <key>`. Health and metrics endpoints take none.

**Key format.** `ipv_<keyid>_<secret>`, matching `^ipv_([a-z2-7]{16})_([a-z2-7]{52})$`.

- `keyid`: 10 bytes from `crypto/rand`, base32 (RFC 4648 alphabet, lowercase, no padding).
- `secret`: 32 bytes from `crypto/rand`, encoded the same way.
- Stored: `id = keyid`, `secret_hash = SHA-256(secret as ASCII)`. The full key is returned once, at creation, and never logged.

**Verifying a request**

1. Missing header, wrong scheme, or a key not matching the pattern → 401 `unauthenticated`, with `WWW-Authenticate: Bearer`.
2. If the keyid matches the environment admin key's keyid, compare against it; otherwise load the `api_keys` row by id. No row → 401.
3. Compare `SHA-256(secret)` to the stored hash with `crypto/subtle.ConstantTimeCompare`. Mismatch → 401.
4. `revoked_at` set, or `expires_at` in the past (database time) → 401. Do not cache key rows, so revocation takes effect on the next request.
5. The route's required kind differs from the key's kind → 403 `forbidden`. Admin routes need `admin`, `/v1/worker/*` needs `worker`, all other `/v1` routes need `client`.
6. Client keys: load the client's realms. A client with no realms gets 403 `realm_not_allowed` on every call.
7. Record `last_used_at` asynchronously, at most once a minute per key.

**Environment admin key.** At startup, parse `IPVALET_ADMIN_KEY` (or its `_FILE`) into keyid and secret hash, or take `IPVALET_ADMIN_KEY_HASH` (`<keyid>:<64 hex chars>`) directly. Hold only the keyid and hash in memory. Requests made with it have actor `admin:env` in the audit log. It cannot be listed or revoked through the API. `hash-key` reads a full key on stdin and prints `<keyid>:<hex sha256 of secret>`.

**Rate limiting.** Client keys only; admin and worker keys are never limited. The limit is the client's `rate_limit_per_minute`, or `IPVALET_DEFAULT_RATE_LIMIT` when NULL; 0 means off, which is the default. Use one token bucket per key (`rate.Limit(n/60)`, burst `n`), kept in memory and evicted after 10 minutes idle. Over the limit → 429 `rate_limited` with `Retry-After` in seconds.

**Request context.** After authentication, handlers receive: actor string (key id or `admin:env`), key kind, client id and realms (client keys), worker id (worker keys).

## Normalisation and rule evaluation

**Names.** Realms match `^[a-z0-9][a-z0-9._-]{0,62}$`. Users and groups are 1 to 256 characters, no control characters, and never `*`. All comparisons are exact and case-sensitive; nothing is lowercased or trimmed. Invalid names → 400 `invalid_request`.

**TTL.** A string: `unlimited`, or a positive integer with one unit `s`, `m`, `h` or `d` (`3600s`, `90m`, `36h`, `30d`), at most `3650d`. Anything else → 400 `invalid_request`. TTLs are returned in the largest unit that divides them exactly.

**Prefix normalisation**, in this order:

1. Parse with `netip.ParsePrefix`; if there is no `/`, parse with `netip.ParseAddr` and use the full length (/32 or /128). Zoned addresses (`fe80::1%eth0`) are invalid.
2. IPv4-mapped IPv6 (`::ffff:0:0/96` and inside it) becomes IPv4: unmap the address and subtract 96 from the length. A mapped prefix shorter than /96 is invalid.
3. Clear host bits with `Prefix.Masked()`; `203.0.113.7/24` becomes `203.0.113.0/24`.
4. The canonical form is `Prefix.String()`, and it is what the response returns and the database stores.

Any failure → the submission's `invalid_prefix` result.

**Selector match.** Subscriptions and all four rule lists use the same test. A NULL field matches anything.

```go
func matches(selRealm, selUser, selGroup *string, realm, user, group string) bool {
    return (selRealm == nil || *selRealm == realm) &&
        (selUser == nil || *selUser == user) &&
        (selGroup == nil || *selGroup == group)
}
```

**Rule evaluation.** Each candidate entry (realm, user, group, prefix, ttl) is evaluated against its realm's four lists, each ordered by `position`. The first rule whose selector matches decides; IP rules add a prefix test.

```go
// IP rules: the first rule whose selector matches AND whose prefix overlaps decides.
for _, r := range ipRules {
    if !matches(&r.Realm, r.User, r.Group, e.Realm, e.User, e.Group) { continue }
    if r.Prefix.Addr().Is4() != p.Addr().Is4() || !r.Prefix.Overlaps(p) { continue }
    if r.Action == "deny" { return reject("ip_denied") }
    if r.Prefix.Bits() <= p.Bits() && r.Prefix.Contains(p.Addr()) { return ok }
    return reject("ip_denied") // an ACCEPT that only partly covers the prefix
}
return reject("ip_denied") // no rule matched: default deny

// Prefix rules: first selector match; its limit for p's family, NULL = no limit.
// p.Bits() < limit -> reject("prefix_too_broad", limit). No rule -> ok.

// TTL rules: first selector match. max NULL -> ok (unlimited allowed).
// Requested "unlimited" or requested > max -> reject("ttl_exceeded", max). No rule -> ok.
// An existing entry exceeds max when expires_at - now > max, or it is unlimited.

// Cap rules: C = first selector match for the candidate. No rule -> ok.
// S = { candidate prefix } ∪ { prefix of every live, unexpired entry of (realm, user)
//       whose own first-matching cap rule is C }.
// len(S) > C.MaxPrefixes -> reject("cap_exceeded", C.MaxPrefixes).
```

A live entry has `deleted_at IS NULL`; an unexpired one has `expires_at IS NULL OR expires_at > now()`, using database time.

**Routing.** A candidate is routed if some worker handles the prefix's family (`ipv4` or `ipv6`) and has a subscription matching (realm, user, group). Otherwise it gets `no_subscriber`.

**Seeding a realm.** In the same transaction as `INSERT INTO realms`:

| List | Positions | Rules (all with user and group `*`) |
| --- | --- | --- |
| IP | 1 to 25 | `deny` for each reserved range in the design doc, IPv4 then IPv6, in the order listed there |
| IP | 26, 27 | `accept 0.0.0.0/0`, `accept ::/0` |
| Prefix | 1 | `min_len_v4 = IPVALET_DEFAULT_PREFIX_V4`, `min_len_v6 = IPVALET_DEFAULT_PREFIX_V6` |
| TTL | 1 | `max_ttl_seconds = IPVALET_DEFAULT_TTL` |
| Cap | none |  |

Seeded rules get the description `seeded default` and are ordinary rules afterwards: editable, reorderable and deletable.

**Inserting a rule without a position.** It goes immediately before the list's first catch-all, or at the end if there is none. A catch-all has user and group `*`; for IP rules its prefix must also be `/0`.

**Warnings, returned with the admin response but never blocking.**

- `rule_shadowed`: an earlier rule in the same list has a selector covering this rule's (each field `*` or equal) and, for IP rules, a prefix of the same family that contains this rule's prefix. That earlier rule always decides first. Warnings cover the whole list after the change.
- `cross_realm_selector`: a subscription with realm `*` but a specific user or group.

## Submissions

`POST /v1/submissions` (client key) creates or replaces one entry per group, all or nothing.

```json
{
  "realm": "authentik",
  "user": "patrick",
  "groups": ["fwusers", "guests"],
  "prefix": "2001:db8:1234:5678::/64",
  "ttl": "30d"
}
```

- `realm`: optional only when the key's client has exactly one realm.
- `groups`: 1 to 32 names; duplicates are removed.
- Unknown fields → 400 `invalid_request` (decode with `DisallowUnknownFields`).

**Transaction**

1. Validate the body's shape and names (400 on failure), and normalise the prefix.
2. Begin a `READ COMMITTED` transaction.
3. `SELECT value FROM revision_counter FOR UPDATE`. This serialises every writer, so cap checks and revision order cannot race.
4. Load the realm's four rule lists, the workers with their subscriptions, and the user's live entries in the realm.
5. For each group, build a candidate and run the checks in order: client scope (the realm is bound to the client), prefix validity, routing, IP rules, prefix rules, TTL rules, cap rules. Run them for every group, so the response lists every failure.
6. If any candidate failed: roll back and return 422.
7. Otherwise `UPDATE revision_counter SET value = value + 1 RETURNING value` gives `R`, and `submission_id` is a new UUID.
8. For each candidate, insert or replace (below) with `revision = R`, `expires_at = now() + ttl` (NULL when unlimited), `client_id`, `key_id`, `updated_at = now()`.
9. Write one audit row per entry (`entry.create` or `entry.replace`), then `NOTIFY ipvalet_changes, '<R>'`.
10. Commit, then compute applied state and respond 201.

**Replace.** Insert, or replace when a row with `deleted_at IS NULL` already holds the same (realm, user, group, prefix), using `INSERT … ON CONFLICT (realm, username, grp, prefix) WHERE deleted_at IS NULL DO UPDATE`. A replace keeps `id` and `created_at` and overwrites `submission_id`, `expires_at`, `revision`, `client_id`, `key_id` and `updated_at`. This revives an expired entry and can shorten a longer one.

**Response 201**

```json
{
  "submission_id": "6b0c…",
  "prefix": "2001:db8:1234:5678::/64",
  "entries": [
    { "id": "a1f2…", "realm": "authentik", "user": "patrick", "group": "fwusers",
      "prefix": "2001:db8:1234:5678::/64", "expires_at": "2026-12-24T18:00:00Z",
      "replaced": false, "state": "pending",
      "workers": [ { "label": "Home network", "state": "pending" } ] }
  ]
}
```

**Response 422**

```json
{
  "error": {
    "code": "submission_rejected",
    "message": "1 of 2 groups failed",
    "results": [
      { "group": "fwusers", "ok": true },
      { "group": "guests", "ok": false, "code": "ttl_exceeded", "limit": { "max_ttl": "1d" } }
    ]
  }
}
```

`limit` is present for `ttl_exceeded` (`max_ttl`), `prefix_too_broad` (`min_prefix_len`) and `cap_exceeded` (`max_prefixes`). Each group reports only its first failing check.

**Deleting.** `DELETE /v1/entries/{id}` and `DELETE /v1/submissions/{id}` follow the same transaction pattern: lock the counter, check that every affected entry is in one of the client's realms (otherwise 404), bump to `R`, record removals (below), set `deleted_at = now()`, `deleted_by = actor`, `deleted_revision = R`, audit, notify, commit. Deleting an entry that is already deleted returns 404.

**Recording removals.** Every soft delete first inserts an `entry_removals` row `(entry, worker, R)` for each worker that matches the entry at that moment, in the same transaction and before any other change in it that stops workers matching (a realm deletion deletes its subscriptions after soft-deleting the entries). Every routing change (subscription deletion, worker family change) inserts a row `(entry, worker, R)` for each entry that is not deleted, expired ones included, that the worker matched before the change and no longer matches. On conflict keep the greater revision.

## Revisions and change signals

**What a revision is.** One global counter (the `revision_counter` row), not one per worker. Each entry records the revision at which it was last written; each worker records the highest revision it has reported applying (`applied_revision`) and the revision of its last subscription or family change (`subscriptions_revision`). Applied state is worked out by comparing these numbers. The counter is a `bigint`: at 1,000 bumps a second it lasts about 292 million years.

**Why a locked counter, not a sequence.** Applied state compares a worker's `applied_revision` with entry revisions, so this must hold: once a reader sees revision R, every change with revision ≤ R is visible to it. A Postgres sequence breaks that: transaction A takes 10, B takes 11 and commits first, a worker fetches at 11 and confirms it, then A commits revision 10, which would wrongly read as applied. The single-row counter avoids this because it is locked until commit, so commit order equals revision order.

**What bumps the revision.** Every write that can change any worker's desired state takes the counter lock first and increments it once per transaction:

- Entries: create, replace, delete (client or admin), and realm deletion (which soft-deletes the realm's entries).
- Subscriptions: create and delete. Also set the worker's `subscriptions_revision = R`.
- Workers: a change to `ipv4` or `ipv6`. Also set that worker's `subscriptions_revision = R`.
- Removals and shortenings that the impact check applies (see Client and admin endpoints).

Rule changes that remove or shorten nothing, client and key changes, worker name and label changes, worker deletion and status reports do not bump the revision.

**Notifications.** Two channels, both sent inside the writing transaction so they fire only on commit:

| Channel | Payload | Sent when |
| --- | --- | --- |
| `ipvalet_changes` | the new revision, as decimal text | every revision bump |
| `ipvalet_status` | the worker id | a status report is stored |

Each API instance holds one dedicated connection running `LISTEN` on both channels and feeds an in-process hub. If that connection drops, reconnect with backoff, then wake every connected stream, since notifications may have been missed.

**SSE hub.**

- Each worker stream and client stream registers a buffered channel (capacity 1) with the hub.
- A notification does a non-blocking send to each subscriber, so a slow stream gets one pending wake-up, never a backlog.
- Worker streams wake on `ipvalet_changes`.
- Client streams wake on both channels and on their own recheck timer (`IPVALET_CLIENT_EVENTS_RECHECK`), because expiry happens by time and sends no notification.
- On each wake-up a stream re-checks that its key is still valid and ends if it is not.

**SSE format.** Set `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`, and flush after every event. Send `: ping` every `IPVALET_SSE_HEARTBEAT`. Lift the server's write and read deadlines for these routes only, with `http.ResponseController`; an expired read deadline would otherwise cancel the request context.

## Worker endpoints

All three require a worker key; the worker is the key's worker.

**`GET /v1/worker/desired-state`.** Run in one `REPEATABLE READ READ ONLY` transaction, so the revision, the time and the rows come from one snapshot:

```sql
SELECT value FROM revision_counter;          -- R
SELECT now();                                -- generated_at (database time)
SELECT e.prefix,
       CASE WHEN bool_or(e.expires_at IS NULL) THEN NULL
            ELSE max(e.expires_at) END AS expires_at
FROM entries e
WHERE e.deleted_at IS NULL
  AND (e.expires_at IS NULL OR e.expires_at > now())
  AND ((family(e.prefix) = 4 AND $ipv4) OR (family(e.prefix) = 6 AND $ipv6))
  AND EXISTS (
    SELECT 1 FROM subscriptions s
    WHERE s.worker_id = $worker
      AND (s.realm    IS NULL OR s.realm    = e.realm)
      AND (s.username IS NULL OR s.username = e.username)
      AND (s.grp      IS NULL OR s.grp      = e.grp))
GROUP BY e.prefix
ORDER BY e.prefix;
```

Response 200:

```json
{
  "revision": 1842,
  "generated_at": "2026-11-24T17:00:00.123456Z",
  "next_change_at": "2026-11-25T17:00:00Z",
  "families": ["ipv4", "ipv6"],
  "entries": [
    { "prefix": "203.0.113.7/32", "expires_at": "2026-11-25T17:00:00Z" },
    { "prefix": "2001:db8:1234:5678::/64", "expires_at": null }
  ]
}
```

- `next_change_at`: the earliest non-null `expires_at` in `entries`, or null.
- Timestamps are RFC 3339 in UTC; `generated_at` keeps microseconds.
- `ETag`: a quoted hex SHA-256 over `families` plus each entry as `prefix expires_at` (`-` for null), one per line in the order above. It excludes `revision` and `generated_at`, so it changes only when this worker's content changes.
- Headers on every response, 200 or 304: `IPValet-Revision: <R>`, `IPValet-Generated-At: <generated_at>`.
- `If-None-Match` equal to the current ETag → 304 with no body. The worker still reports status with the revision and time from those headers, since its state is current at that revision.

**`GET /v1/worker/events`.** An SSE stream. On connect, and on every hub wake-up, send:

```
id: 1842
event: changed
data: {"revision":1842}

```

Always send one event immediately on connect, whatever `Last-Event-ID` says; the worker's fetch with `If-None-Match` makes that cheap. Count connected worker streams for metrics.

**`POST /v1/worker/status`**

```json
{ "instance": "unifi-1", "version": "0.3.0", "revision": 1842,
  "generated_at": "2026-11-24T17:00:00.123456Z",
  "rejected": [ { "prefix": "2001:db8::/32", "code": "prefix_too_broad", "detail": "…" } ] }
```

Or, on failure: `{ "instance": "unifi-1", "version": "0.3.0", "revision": 1842, "error": "controller timeout" }`.

- Validation (400 `invalid_request` otherwise):
  - `instance` (the reporting process, for example its host name) is 1 to 128 characters; `version` is at most 64.
  - `revision` is ≤ the current counter value.
  - Exactly one of `error` (1 to 2000 characters) or `generated_at` is present; `generated_at` is not in the future; `rejected` is only allowed with `generated_at`.
  - At most 200 `rejected` items, each with a valid prefix and a code from the worker codes in Errors; `detail` is at most 200 characters. The first item for a prefix wins. At these limits the largest report is about 59 KB, inside the default 64 KiB body limit.
- Always: set `last_seen_at = now()`, `last_instance` and `last_version`.
- Success with `revision ≥ applied_revision`: set `applied_revision = revision` and `applied_generated_at = greatest(applied_generated_at, generated_at)`, then replace all of the worker's `worker_rejections` with the reported list (stored with `revision`).
- Success with `revision < applied_revision`: a stale report. Change nothing but the "always" fields.
- Error: set `last_error` and `last_error_at`; leave the applied fields and rejections alone.
- Then `NOTIFY ipvalet_status, '<worker id>'` and respond 200 `{ "applied_revision": <value now stored> }`. Do not audit status reports; log them at debug level.

Workers may repeat a status report as a heartbeat; that only refreshes `last_seen_at`.

## Applied state

Applied state is computed when read, never stored. Load all workers with their subscriptions once per request (there are few), plus the `worker_rejections` rows for the prefixes involved and the `entry_removals` rows for the entries involved, then evaluate each entry in Go:

```go
// gone reports whether worker w has removed entry e, given the revision from
// which w no longer holds it (an entry_removals row).
func gone(e Entry, w Worker, rev int64) bool {
    return w.AppliedRevision >= rev ||
        (e.ExpiresAt != nil && w.AppliedGeneratedAt != nil && !w.AppliedGeneratedAt.Before(*e.ExpiresAt))
}

func entryState(e Entry, workers []Worker, rej Rejections, rem Removals, now time.Time) (string, []WorkerState) {
    rows := rem[e.ID] // worker id -> revision

    // Ended entries: removing until every worker that held them has confirmed.
    if e.DeletedRevision != nil || (e.ExpiresAt != nil && !now.Before(*e.ExpiresAt)) {
        final := "removed"
        if e.DeletedRevision == nil { final = "expired" }
        overall, per := final, []WorkerState{}
        for _, w := range workers {
            rev, onRecord := rows[w.ID]
            var ok bool
            switch {
            case e.DeletedRevision != nil: // deleted: the workers on record
                if !onRecord { continue }
                ok = gone(e, w, rev)
            case routes(w, e): // expired, still matched
                ok = w.AppliedGeneratedAt != nil && !w.AppliedGeneratedAt.Before(*e.ExpiresAt)
            case onRecord: // expired, no longer matched
                ok = gone(e, w, rev)
            default:
                continue
            }
            s := final
            if !ok { s = "removing"; overall = "removing" }
            per = append(per, WorkerState{Label: w.Label, State: s})
        }
        return overall, per
    }

    per := []WorkerState{}
    var nMatched, nPending, nRejected int
    for _, w := range workers {
        if !routes(w, e) {
            // A worker that stopped matching is listed until it confirms; it does not count.
            if rev, onRecord := rows[w.ID]; onRecord && !gone(e, w, rev) {
                per = append(per, WorkerState{Label: w.Label, State: "removing"})
            }
            continue
        }
        nMatched++
        need := max(e.Revision, w.SubscriptionsRevision)
        switch {
        case w.AppliedRevision < need:
            per = append(per, WorkerState{Label: w.Label, State: "pending"}); nPending++
        case rej.Has(w.ID, e.Prefix):
            per = append(per, WorkerState{Label: w.Label, State: "rejected", Code: rej.Code(w.ID, e.Prefix)}); nRejected++
        default:
            per = append(per, WorkerState{Label: w.Label, State: "active"})
        }
    }
    switch {
    case nMatched == 0:          return "unrouted", per
    case nPending > 0:           return "pending", per
    case nRejected == nMatched:  return "rejected", per
    case nRejected > 0:          return "partial", per
    default:                     return "active", per
    }
}
```

Notes for the implementer:

- Pending is checked before rejected. A rejection on record belongs to the worker's last applied revision, so it counts only once the worker has caught up with the entry.
- `now` is the database time of the reading transaction (`SELECT now()`).
- A worker that is deleted takes its `entry_removals` rows with it; there is no process left to confirm anything.
- Order `workers` in responses by label, then worker id, so output is stable.

**Overall states and their meaning to clients**

| State | Meaning |
| --- | --- |
| `active` | Every matching worker has applied it |
| `pending` | At least one matching worker has not caught up |
| `partial` | Some workers rejected it, the rest applied it |
| `rejected` | Every matching worker rejected it |
| `unrouted` | No worker matches it (only after a routing change) |
| `removing` | Deleted or expired, but a worker that held it has not yet confirmed removal |
| `removed` | Deleted, and every worker that held it has confirmed |
| `expired` | Expired, and every worker that held it has confirmed |

## Client and admin endpoints

**Conventions**

- JSON in and out, UTF-8, and `snake_case` fields.
- In the API a wildcard is the string `"*"`; the database stores NULL.
- Timestamps are RFC 3339 UTC; durations use the TTL syntax.
- Lists take `?limit=` (default 100, max 1000) and `?cursor=`, and return `{ "items": […], "next_cursor": "…" | null }`. The cursor is opaque (base64 of the last sort key).
- Unknown body fields and unknown query parameters → 400. Path ids that do not exist, or that lie outside a client's realms → 404. An unknown method on a known path → 405 `method_not_allowed` with `Allow`.
- Every successful admin mutation writes an audit row.
- Admin mutation responses are the object's fields plus a top-level `warnings` array; impact-checked changes add `impact` (on dry runs and confirmed changes), `enforced` (on confirmed changes) and `dry_run: true` (on dry runs).

**Client endpoints**

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/submissions` | see Submissions | 201, see Submissions |
| `DELETE /v1/submissions/{id}` | none | 200 `{ "deleted": [<entry ids>] }` |
| `GET /v1/entries` | filters `realm`, `user`, `group`, `prefix`, `state`, `include_ended` (default false) | 200 list of entries, by creation time |
| `GET /v1/entries/{id}` | none | 200 entry |
| `DELETE /v1/entries/{id}` | none | 200 entry (usually state `removing`) |
| `GET /v1/events` | none | SSE stream, below |

An entry, as clients see it:

```json
{ "id": "…", "submission_id": "…", "realm": "authentik", "user": "patrick",
  "group": "fwusers", "prefix": "203.0.113.7/32", "expires_at": "…" | null,
  "created_at": "…", "updated_at": "…", "deleted_at": null,
  "state": "active", "workers": [ { "label": "Home network", "state": "active" } ] }
```

- "Ended" means deleted or expired. Lists return only live, unexpired entries unless `include_ended=true`.
- The `state` filter runs after state is computed, so a page may hold fewer than `limit` items while `next_cursor` is still set.
- A `realm` filter outside the client's realms → 403 `realm_not_allowed`.

**Client events.** On connect, compute the state of every entry in the client's realms that is live or ended within the last 24 hours. Send nothing for this baseline. On each wake-up, recompute and send one event per entry whose overall state changed:

```
event: entry
data: {"id":"…","state":"active"}

```

**Admin endpoints** (all under `/v1/admin`)

| Resource | Routes | Fields and behaviour |
| --- | --- | --- |
| Realms | `GET /realms`, `POST /realms`, `GET /realms/{name}`, `DELETE /realms/{name}` | `{ name }`. POST seeds the default rules. DELETE soft-deletes the realm's live entries (one revision bump, removals recorded first) and cascades its rules, client bindings and subscriptions (bumping `subscriptions_revision` on affected workers). It needs no confirmation and returns `{ name, entries_removed, rules_deleted, subscriptions_deleted, clients_unbound, revision }`. |
| Clients | `GET /clients`, `POST /clients`, `GET /clients/{id}`, `PATCH /clients/{id}`, `DELETE /clients/{id}` | `{ name, realms[], rate_limit_per_minute \| null }`. `realms` needs at least one existing realm. DELETE cascades the client's keys; its entries keep a NULL `client_id`. |
| Workers | `GET /workers`, `POST /workers`, `GET /workers/{id}`, `PATCH /workers/{id}`, `DELETE /workers/{id}` | `{ name, label, ipv4, ipv6 }`, at least one family true. Responses add `applied_revision`, `applied_generated_at`, `subscriptions_revision`, `last_seen_at`. Changing a family bumps the revision. PATCH of families and DELETE go through the impact check. |
| Subscriptions | `GET /workers/{id}/subscriptions`, `POST /workers/{id}/subscriptions`, `DELETE /subscriptions/{id}` | `{ realm, user, group }`, each a name or `"*"`; set only by admins. No PATCH: delete and create instead. Every change bumps the revision; DELETE goes through the impact check. |
| Keys | `GET /keys`, `POST /keys`, `GET /keys/{id}`, `POST /keys/{id}/revoke` | POST `{ kind, client_id \| worker_id, name, expires_at? }` returns 201 with the key record and `"key": "ipv_…"`, shown only this once. List filters: `kind`, `client_id`, `worker_id`. A key record never contains the secret or its hash. |
| Rules | `GET`, `POST /realms/{realm}/rules/{list}`; `PATCH`, `DELETE /realms/{realm}/rules/{list}/{id}`; `PUT /realms/{realm}/rules/{list}/order` | `list` is `ip`, `prefix`, `ttl` or `cap`. Common fields `{ user, group, position?, description? }`. IP adds `prefix, action`; prefix adds `min_len_v4, min_len_v6` (null = no limit); TTL adds `max_ttl` (a duration or `"unlimited"`); cap adds `max_prefixes`. `order` takes `{ "ids": […] }`, which must list every rule in that list exactly once. All changes go through the impact check. |
| Entries | `GET /entries`, `GET /entries/{id}`, `DELETE /entries/{id}` | Like the client view, across all realms, plus `client_id`, `key_id`, `revision`, `deleted_by`, and worker `id`, `name` and `last_seen_at`. Extra filters: `client_id`, `worker_id` (entries the worker matches). |
| Health | `GET /workers/{id}/health`, `GET /health` | Per worker: `applied_revision`, current revision, `lag`, `applied_generated_at`, `last_seen_at`, `last_error`, `last_error_at`, `last_instance`, `last_version`, `worker_streams` (on the answering API instance), rejections. `/health` lists every worker. |
| Audit | `GET /audit` | Filters `since`, `until`, `actor`, `realm`, `action`; newest first. |

**The impact check.** It applies to rule changes of any kind, subscription deletion, worker deletion, and worker family changes. No entry is ever left in place that fails a rule.

1. Inside one transaction, take the counter lock, read the entries the change can affect, and apply the change. For rules that is every live, unexpired entry in the realm; for routing changes, every entry the worker matched before the change.
2. Work out the impact on those entries:
   - **Rule changes.** Entries an IP or prefix rule now rejects: `remove`. Then, for each user and cap rule, if the user's distinct prefixes decided by that rule exceed the limit, keep the most recently submitted prefixes (latest `updated_at`) up to the limit and `remove` the entries holding the others (`cap_exceeded`). Then, for the remaining entries, a TTL rule whose max is shorter than the entry's lifetime left (or finite when the entry is unlimited): `shorten` (`ttl_exceeded`).
   - **Routing changes.** Entries no worker matches any more: `none` (`unrouted`). They fail no rule and stay. Record removals for the worker (see Submissions).
   - Each entry gets at most one impact item: `{ entry_id, realm, user, group, prefix, effect, action }`.
3. With `?dry_run=true`, roll back and return 200 with `impact` and `warnings`.
4. With no impact, commit and return 200 (201 for a created rule).
5. With impact and no `?confirm=true`, roll back and return 409 `confirmation_required` with `impact`.
6. With `?confirm=true`, apply every action in the same transaction and commit: `remove` soft-deletes the entry (recording removals first), and `shorten` sets `expires_at = now() + max_ttl` and `revision = R`, leaving `updated_at` alone. Bump the revision once if anything changed. Return `impact` and `enforced: { "shortened": n, "removed": n }`.

## Errors

Every error response has the same envelope; `results`, `impact` and `fields` appear only where noted.

```json
{ "error": { "code": "invalid_request", "message": "groups: must not be empty",
             "fields": { "groups": "must not be empty" } } }
```

`message` is for humans and may change; clients act on `code`. Never put secrets, SQL or stack traces in an error. Log 500s with a request id and return that id in the `X-Request-Id` header on every response.

**Request-level codes**

| HTTP | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, unknown fields, invalid names, TTLs or query parameters (`fields` says which) |
| 401 | `unauthenticated` | Missing, malformed, unknown, revoked or expired key |
| 403 | `forbidden` | Wrong key kind for the route |
| 403 | `realm_not_allowed` | A client with no realms, or a realm-scoped read outside the client's realms |
| 404 | `not_found` | Unknown id or path, or outside the caller's realms |
| 405 | `method_not_allowed` | Unknown method on a known path (`Allow` lists the methods) |
| 409 | `conflict` | A unique name already exists (realm, client, worker, subscription) |
| 409 | `confirmation_required` | The impact check found affected entries (`impact`) |
| 413 | `body_too_large` | Body over `IPVALET_MAX_BODY_BYTES` |
| 422 | `submission_rejected` | A submission check failed (`results`) |
| 429 | `rate_limited` | Over the key's rate limit (`Retry-After`) |
| 500 | `internal` | Anything unexpected |
| 503 | `unavailable` | Database unreachable, or the server is shutting down |

**Submission result codes** (in `results[].code`), in check order: `realm_not_allowed`, `invalid_prefix`, `no_subscriber`, `ip_denied`, `prefix_too_broad`, `ttl_exceeded`, `cap_exceeded`.

**Worker rejection codes** (accepted in status reports, shown to clients as `workers[].code`): `prefix_too_broad`, `address_not_allowed`, `family_unsupported`, `capacity_exceeded`, `invalid`.

**Impact effects and actions**: `ip_denied`, `prefix_too_broad`, `cap_exceeded` → `remove`; `ttl_exceeded` → `shorten`; `unrouted` → `none`.

Codes may be added in later versions; a code's meaning never changes. The full catalogue is in `spec/openapi.yaml` as enums.

## Background jobs, observability and shutdown

**Startup order for `serve`**

1. Parse and validate configuration.
2. Connect the pool, retrying with backoff for up to 60 s.
3. Run migrations under a Postgres session advisory lock (goose's Postgres session locker), so concurrent instances wait their turn.
4. Start the `LISTEN` connection and the hub.
5. Start the purge job, then the HTTP listeners.

**Purge job.** Every `IPVALET_PURGE_INTERVAL`, in a transaction that first takes `pg_try_advisory_xact_lock(<fixed constant>)` and skips the run if the lock is held:

- Delete entries whose `deleted_at` is older than `IPVALET_RETENTION_ENTRIES`, or that are not deleted and whose `expires_at` is older than it. Their `entry_removals` rows go with them.
- Delete audit rows older than `IPVALET_RETENTION_AUDIT`.
- Delete in batches of 1000 rows. Purging bumps no revision, since purged rows are already absent from every desired state.

Expiry itself needs no job: desired state and applied state both compare `expires_at` with the database clock when read.

**HTTP server.** `ReadHeaderTimeout` 10 s, `ReadTimeout` 30 s, `WriteTimeout` 30 s (lifted per request for SSE routes), `IdleTimeout` 120 s. Reject bodies whose `Content-Length` exceeds the limit up front, and cap the rest with `http.MaxBytesReader`.

**Health.** On the API listener, without authentication:

- `GET /healthz` returns 200 `ok` whenever the process is serving.
- `GET /readyz` returns 200 when `SELECT 1` succeeds within 2 s and the `LISTEN` connection is up, otherwise 503.

**Metrics.** On `IPVALET_METRICS_ADDR` only, so they are not exposed through the proxy. Route labels use the route pattern, never the raw path. Worker gauges are read from the database at scrape time by a custom collector.

| Metric | Type | Labels |
| --- | --- | --- |
| `ipvalet_http_requests_total` | counter | `route`, `method`, `status` |
| `ipvalet_http_request_duration_seconds` | histogram | `route`, `method` |
| `ipvalet_submissions_total` | counter | `result` (`accepted` or the first failing code) |
| `ipvalet_revision` | gauge | none |
| `ipvalet_worker_applied_revision` | gauge | `worker` (name) |
| `ipvalet_worker_revision_lag` | gauge | `worker` |
| `ipvalet_worker_last_seen_timestamp_seconds` | gauge | `worker` |
| `ipvalet_worker_rejections` | gauge | `worker` |
| `ipvalet_worker_streams` | gauge | `worker` |
| `ipvalet_client_streams` | gauge | none |
| `ipvalet_entries_live` | gauge | `realm` |

**Logging.** `slog` JSON to stdout. One access line per request: method, route, status, duration, actor, request id (`/healthz` and `/readyz` at debug level). Never log keys, the `Authorization` header or request bodies.

**Shutdown.** On SIGTERM or SIGINT:

1. Stop accepting connections and end all SSE streams; workers and clients reconnect on their own.
2. Wait up to `IPVALET_SHUTDOWN_TIMEOUT` for in-flight requests.
3. Stop the purge job, close the `LISTEN` connection and the pool, and exit 0.

## Acceptance tests

Each item is at least one automated test against a real Postgres. Unit tests for pure functions are welcome in addition; they do not replace these.

**Keys and auth**

- [x] Malformed, unknown, wrong-secret, revoked and expired keys each return 401; the wrong key kind for a route returns 403.
- [x] `create-admin-key` prints a working key, and the database holds only its hash.
- [x] `IPVALET_ADMIN_KEY`, `_FILE` and `_HASH` each authenticate; setting two of them fails startup.
- [x] Revoking a key takes effect on the very next request.
- [x] Rate limiting is off by default; with a limit set, the request over it returns 429 with `Retry-After`.

**Normalisation and rules**

- [x] `203.0.113.7/24` is stored and returned as `203.0.113.0/24`; `::ffff:203.0.113.7` becomes `203.0.113.7/32`; a bare address gets /32 or /128.
- [x] With `DENY 10.0.0.0/8` above `ACCEPT 0.0.0.0/0`, `8.0.0.0/6` is rejected `ip_denied` and `1.2.3.4/32` is accepted.
- [x] An ACCEPT that only partly covers a prefix rejects it; an empty IP rule list rejects everything.
- [x] First match wins in each list, and reordering changes the outcome.
- [x] Prefix rule: a /48 is rejected under the seeded /64 limit, with `min_prefix_len` 64 in the result.
- [x] TTL rule: a TTL over the max returns `ttl_exceeded` with `max_ttl`; `unlimited` is rejected under a finite max; with no TTL rule, `unlimited` is accepted.
- [x] Cap rule: three groups, one prefix count once; a fourth distinct prefix under a limit of 3 is rejected; entries under a different cap rule do not count.
- [x] A new realm has the seeded rules, using the `IPVALET_DEFAULT_*` values.
- [x] Shadowed rules and cross-realm subscriptions produce warnings without blocking.

**Submissions**

- [x] A group with no subscriber (including a family mismatch) makes the whole submission fail with `no_subscriber`, and nothing is written.
- [x] Every failing group is listed, each with its first failing check.
- [x] Re-submitting the same (realm, user, group, prefix) keeps the id, sets the expiry to now plus the new TTL (a shorter TTL shortens it), and bumps the revision.
- [x] Re-submitting an expired entry revives it.
- [x] Concurrent submissions cannot exceed a cap (run them in parallel).
- [x] A client cannot see or delete entries outside its realms (404).

**Revisions, desired state and applied state**

- [x] Commit order equals revision order. Hold one writer open, commit a second, and show the second waits on the counter lock.
- [x] Desired state has one item per prefix, carries the latest expiry (or null if any entry is unlimited), excludes expired, deleted and other-family entries, and sets `next_change_at`.
- [x] Unchanged content returns 304 with `IPValet-Revision`; a change to another worker's entries leaves this worker's ETag unchanged.
- [x] A status report raises `applied_revision` but never lowers it; a stale report changes nothing but `last_seen_at`; an error report leaves the applied state unchanged.
- [x] The largest valid status report (200 rejections, 200-character details) is accepted within the default body limit; 201 rejections or a longer detail is 400.
- [x] Every applied state in the Applied state table is reachable. A new subscription makes old entries `pending` on that worker, not `active`.
- [x] A deleted entry stays `removing` until the worker reports the deletion revision; an expired one until `applied_generated_at` passes its expiry.
- [x] A worker that stops matching an entry (subscription deleted, family dropped) keeps it `removing` on that worker until it confirms, whether the entry is deleted, expired or still live.
- [x] A worker's SSE stream receives `changed` within a second of a committed submission. The test LISTENs on a second API instance in the same test to prove fan-out between instances.

**Admin**

- [x] A rule change with affected entries returns 409 `confirmation_required` with `impact` (each item with `effect` and `action`). `dry_run` changes nothing. `confirm=true` shortens or removes the entries and bumps the revision once; afterwards no live entry in the realm fails a rule.
- [x] A cap added over existing entries removes the least recently submitted prefixes and keeps the most recent ones.
- [x] Deleting a subscription or a worker family leaves entries that no worker matches `unrouted`, not removed.
- [x] Deleting a realm removes its rules, bindings and subscriptions, and its entries go to `removing` on every worker that held them, including workers whose subscriptions went with the realm, until each confirms.
- [x] A new key's secret appears only in the creation response.

**Operations**

- [x] Two instances starting at once both succeed, and migrations run once.
- [x] The purge job deletes only rows past retention, and two instances never purge at once.
- [x] `/readyz` returns 503 when the database is down.
- [x] After the `LISTEN` connection is killed it reconnects, streams get a `changed` event, and notifications flow again.

## Implementation defaults

The design doc did not settle these; this spec picked a value so the server could be built. Change any of them only with the owner's agreement.

| Topic | Default chosen | Why |
| --- | --- | --- |
| Revision allocation | One locked counter row; all revision-bumping writes are serialised | The only simple way to make "applied revision ≥ R" trustworthy (see Revisions) |
| Status report | Must echo `generated_at` from the desired state it applied | Needed to confirm removal of expired entries |
| Status report size | At most 200 rejections, details at most 200 characters | The largest report (about 59 KB) fits the default 64 KiB body limit |
| Reporting process | Status reports name their `instance` (free text) | Several processes may share one worker's keys; health shows which one reported |
| Unchanged desired state | 304 carries `IPValet-Revision` and `IPValet-Generated-At` | Otherwise a worker with unchanged state could never confirm newer revisions |
| Key encoding | Lowercase base32: 16-character id, 52-character secret | Has no `_`, so the `ipv_<id>_<secret>` split is unambiguous |
| Realm names | `^[a-z0-9][a-z0-9._-]{0,62}$` | Safe in URLs and logs |
| User and group names | 1 to 256 characters, any printable, case-sensitive | Taken verbatim from identity sources such as authentik |
| Client scope | Realms only; no per-client user or group allow-lists | The realms' rules bound what a client can register |
| Subscriptions | Set by admins for a worker; created and deleted, never edited | A worker cannot widen what it sees; every change already bumps the revision |
| Groups per submission | At most 32 | Bounds the work per request |
| TTL syntax and range | `s`, `m`, `h`, `d` units; at most `3650d`, or `unlimited` | One syntax for requests and configuration |
| Expired entries | Kept as rows until purged; re-submitting one revives it | Keeps one row per (realm, user, group, prefix) |
| Removal confirmation | Recorded per worker in `entry_removals` when an entry is deleted or a worker stops matching it | Confirmation must not depend on the worker still matching the entry |
| Realm deleted under a client | The client keeps working in its other realms; with none left, every call is 403 `realm_not_allowed` | Realm deletion stays a single unblocked action |
| Deleting a client | Its keys are deleted; its entries remain with no client | Entries belong to users, not to the client that sent them |
| Impact check | Confirmation always enforces: remove entries that fail IP or prefix rules, remove the least recently submitted prefixes over a cap, shorten entries over a TTL rule; unrouted entries stay | No entry is ever left failing a rule; routing is not a rule, and keeping unrouted entries lets a re-added subscription restore them |
| TTL on existing entries | Compared by lifetime left, not the TTL originally requested | An entry near the end of its TTL is not shortened for no reason |
| Rate limits | Client keys only | Workers and admins are trusted and few |
| Client event stream | Baseline of entries live or ended in the last 24 h; recheck every 30 s | Catches expiries without a notification |
| Metrics | Separate listener on `:9090` | Not reachable through the public proxy |
| Status reports | Not audited; logged at debug level | They arrive constantly and change no configuration |
