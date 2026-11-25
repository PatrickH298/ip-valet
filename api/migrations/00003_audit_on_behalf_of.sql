-- +goose Up

-- The person an admin key acted for, as the key's holder stated it in the
-- IPValet-On-Behalf-Of header (for example the user signed in to the admin
-- dashboard). NULL when the request named no one.
ALTER TABLE audit_log ADD COLUMN on_behalf_of text
  CHECK (char_length(on_behalf_of) BETWEEN 1 AND 256);

-- +goose Down

ALTER TABLE audit_log DROP COLUMN on_behalf_of;
