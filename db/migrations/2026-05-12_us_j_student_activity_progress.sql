CREATE TABLE IF NOT EXISTS student_activity_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    activity_id UUID NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    current_score INTEGER NOT NULL DEFAULT 0,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    last_question TEXT,
    last_answer TEXT,
    last_interaction_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, activity_id)
);

CREATE INDEX IF NOT EXISTS idx_student_activity_progress_student
    ON student_activity_progress (student_id);

CREATE INDEX IF NOT EXISTS idx_student_activity_progress_activity
    ON student_activity_progress (activity_id);
