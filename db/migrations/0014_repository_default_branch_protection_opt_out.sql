-- Additive per-repository opt-out from automatic default-branch protection.
-- 0 (the default) keeps today's behaviour for every existing repository.
ALTER TABLE repositories ADD COLUMN default_branch_protection_opt_out INTEGER NOT NULL DEFAULT 0 CHECK (default_branch_protection_opt_out IN (0, 1));
