CREATE TABLE IF NOT EXISTS objective_score_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    activity_id UUID NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    objective_index INTEGER NOT NULL,
    objective_text TEXT NOT NULL,
    score_delta INTEGER NOT NULL DEFAULT 1 CHECK (score_delta = 1),
    total_score INTEGER NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, activity_id, objective_index)
);

CREATE INDEX IF NOT EXISTS idx_objective_score_logs_student
    ON objective_score_logs (student_id);

CREATE INDEX IF NOT EXISTS idx_objective_score_logs_activity
    ON objective_score_logs (activity_id);

CREATE INDEX IF NOT EXISTS idx_objective_score_logs_course
    ON objective_score_logs (course_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_activity_scores_activity_student
    ON activity_scores (activity_id, student_id);
