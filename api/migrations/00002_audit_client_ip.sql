-- +goose Up

-- The address of the request that caused each audited change (NULL for
-- changes made by the server itself or from the command line).
ALTER TABLE audit_log ADD COLUMN client_ip inet;

-- +goose Down

ALTER TABLE audit_log DROP COLUMN client_ip;
