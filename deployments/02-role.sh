#!/bin/sh
set -eu
# The gateway receives only its own DB password, never the administrator's.
# Generated credentials contain hexadecimal characters only.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOF
CREATE ROLE aegis LOGIN PASSWORD '$(cat /run/secrets/postgres_password)' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE aegis TO aegis;
GRANT USAGE ON SCHEMA public TO aegis;
GRANT SELECT, INSERT ON TABLE audit_events TO aegis;
EOF
