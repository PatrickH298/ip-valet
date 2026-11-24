-- +goose Up

-- A target stops holding an entry when the entry is deleted, or when the
-- target stops matching it (a subscription is deleted, a family is dropped).
-- Each row records that moment: the target has removed the entry once its
-- applied_revision reaches `revision` (or, for an expired entry, once its
-- applied_generated_at passes the expiry). Removal confirmation reads these
-- rows, so it does not depend on the target still matching the entry.
CREATE TABLE entry_removals (
  entry_id  uuid   NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  target_id uuid   NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  revision  bigint NOT NULL,
  PRIMARY KEY (entry_id, target_id)
);
CREATE INDEX entry_removals_target ON entry_removals (target_id);

-- +goose Down

DROP TABLE entry_removals;
