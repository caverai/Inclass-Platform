-- Migration: Add password_hash to users table
-- Part of US-D: Instructor Authentication APIs
-- Implementation Date: 2026-04-29

ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS password_hash TEXT;
