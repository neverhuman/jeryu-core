-- Additive origin of each old-slug repository alias.
-- 'transfer' (the default) covers every alias written before 0015 by the
-- two-phase transfer journal; 'rename' marks aliases recorded by
-- ForgeCore::rename_repository (a rename, a move to another owner, or both).
ALTER TABLE repository_aliases ADD COLUMN origin TEXT NOT NULL DEFAULT 'transfer' CHECK (origin IN ('transfer', 'rename'));
