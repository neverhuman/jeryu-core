-- Diff identity of a pull-request head: git's per-commit patch ids for
-- base..head, oldest first, recorded by the pusher (Core holds no git
-- objects). A branch whose rule has `dismiss_stale_approvals` off keeps an
-- approval across a push only when the new head's list equals the one the
-- approval was written against.
--
-- Both columns are additive and NULL on every existing row: a head or verdict
-- with no recorded diff identity binds its exact sha only, which is the
-- behaviour those rows were written with.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE pull_requests ADD COLUMN head_patch_ids_json TEXT;
ALTER TABLE reviews ADD COLUMN head_patch_ids_json TEXT;
