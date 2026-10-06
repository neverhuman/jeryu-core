-- Rollback for 0018_waitlist_signups: drop the waitlist.
--
-- Dropping the table deletes every stored address. Use it only before those
-- rows are relied on. After signups exist, recover forward.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
DROP TABLE IF EXISTS waitlist_signups;
