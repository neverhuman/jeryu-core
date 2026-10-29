-- The authority Core verified when it wrote a dismissal of another
-- reviewer's verdict ('repository_admin'). NULL on every other row,
-- including a reviewer's own dismissal.
--
-- Additive and NULL on every existing row. Branch protection honors a
-- dismissal written by someone other than the verdict's author only when this
-- column records the authority, so no existing row changes meaning and a row
-- from an older or foreign writer withdraws nothing.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE reviews ADD COLUMN dismissal_authority TEXT
  CHECK (dismissal_authority IS NULL OR dismissal_authority IN ('repository_admin'));
