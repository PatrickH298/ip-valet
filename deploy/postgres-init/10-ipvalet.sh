#!/bin/sh
# Runs once, when the database volume is first created: a login role for the
# API that owns only its own database and is not a superuser. The password is
# passed to psql as a variable, so it never appears in a command line.
set -eu
pw="$(cat "$IPVALET_DB_PASSWORD_FILE")"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -v pw="$pw" <<'SQL'
CREATE ROLE ipvalet LOGIN PASSWORD :'pw';
CREATE DATABASE ipvalet OWNER ipvalet;
REVOKE ALL ON DATABASE ipvalet FROM PUBLIC;
SQL
