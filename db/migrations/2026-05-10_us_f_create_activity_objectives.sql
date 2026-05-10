-- US-F migration: support activity text + objectives payload for create activity.
-- Safe for existing environments: adds objectives column only if missing.

ALTER TABLE activities
    ADD COLUMN IF NOT EXISTS objectives JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_activities_objectives_gin
    ON activities
    USING GIN (objectives);
