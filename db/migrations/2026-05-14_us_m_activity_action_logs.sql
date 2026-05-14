-- Migration: Add activity_action_logs table for completion events

CREATE TABLE IF NOT EXISTS activity_action_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    activity_id UUID NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (action_type IN ('COMPLETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, activity_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_activity_action_logs_activity
    ON activity_action_logs (activity_id);

CREATE INDEX IF NOT EXISTS idx_activity_action_logs_student
    ON activity_action_logs (student_id);

CREATE INDEX IF NOT EXISTS idx_activity_action_logs_course
    ON activity_action_logs (course_id);

CREATE INDEX IF NOT EXISTS idx_activity_action_logs_created_at
    ON activity_action_logs (created_at DESC);
