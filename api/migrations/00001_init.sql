-- +goose Up

CREATE DOMAIN realm_name AS text
  CHECK (VALUE ~ '^[a-z0-9][a-z0-9._-]{0,62}$');
CREATE DOMAIN ident_name AS text          -- users and groups
  CHECK (VALUE <> '*' AND char_length(VALUE) BETWEEN 1 AND 256
         AND VALUE !~ '[[:cntrl:]]');

-- One row. Every revision-bumping write locks and increments it.
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
  last_instance          text,
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
  updated_at       timestamptz NOT NULL DEFAULT now(),
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

-- The four rule lists share the first nine columns; position is unique per realm and list.
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

CREATE TABLE prefix_rules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  realm       realm_name NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  username    ident_name,   -- NULL = *
  grp         ident_name,   -- NULL = *
  position    integer NOT NULL,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  min_len_v4  smallint CHECK (min_len_v4 BETWEEN 0 AND 32),   -- NULL = no IPv4 limit
  min_len_v6  smallint CHECK (min_len_v6 BETWEEN 0 AND 128),  -- NULL = no IPv6 limit
  UNIQUE (realm, position) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ttl_rules (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  realm           realm_name NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  username        ident_name,   -- NULL = *
  grp             ident_name,   -- NULL = *
  position        integer NOT NULL,
  description     text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  max_ttl_seconds bigint CHECK (max_ttl_seconds > 0),        -- NULL = unlimited
  UNIQUE (realm, position) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE cap_rules (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  realm        realm_name NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  username     ident_name,   -- NULL = *
  grp          ident_name,   -- NULL = *
  position     integer NOT NULL,
  description  text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  max_prefixes integer NOT NULL CHECK (max_prefixes >= 0),
  UNIQUE (realm, position) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE worker_rejections (
  worker_id uuid NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  prefix    cidr NOT NULL,
  code      text NOT NULL,
  detail    text,
  revision  bigint NOT NULL,
  PRIMARY KEY (worker_id, prefix)
);

-- A worker stops holding an entry when the entry is deleted, or when the
-- worker stops matching it (a subscription is deleted, a family is dropped).
-- Each row records that moment: the worker has removed the entry once its
-- applied_revision reaches `revision` (or, for an expired entry, once its
-- applied_generated_at passes the expiry). Removal confirmation reads these
-- rows, so it does not depend on the worker still matching the entry.
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
  action      text NOT NULL,   -- e.g. entry.create, entry.replace, rule.update
  object_type text NOT NULL,
  object_id   text,
  realm       text,
  username    text,
  grp         text,
  prefix      cidr,
  details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at);

-- +goose Down

DROP TABLE audit_log;
DROP TABLE entry_removals;
DROP TABLE worker_rejections;
DROP TABLE cap_rules;
DROP TABLE ttl_rules;
DROP TABLE prefix_rules;
DROP TABLE ip_rules;
DROP TABLE entries;
DROP TABLE api_keys;
DROP TABLE subscriptions;
DROP TABLE workers;
DROP TABLE client_realms;
DROP TABLE clients;
DROP TABLE realms;
DROP TABLE revision_counter;
DROP DOMAIN ident_name;
DROP DOMAIN realm_name;
