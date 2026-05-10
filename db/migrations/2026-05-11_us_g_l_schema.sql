-- Migration: Add activity_scores table for US-L
-- Allows instructors to submit manual grades and logs grading events.

CREATE TABLE IF NOT EXISTS activity_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_id UUID NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score NUMERIC(6,2) NOT NULL,
    grading_type TEXT NOT NULL DEFAULT 'auto' CHECK (grading_type IN ('auto', 'manual')),
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (activity_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_activity_scores_activity ON activity_scores (activity_id);
CREATE INDEX IF NOT EXISTS idx_activity_scores_student ON activity_scores (student_id);