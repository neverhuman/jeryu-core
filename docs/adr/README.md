# Architecture decision records

A decision that binds only jeryu-core lives here, numbered in its own
sequence. Decisions that other repositories of the family have to obey live in
`jeryu-deploy/docs/adr/`, whose README also defines the shape every record
follows: one file per decision, `NNNN-kebab-title.md`, an `# NNNN. Title`
heading, the `Status`, `Date`, `Supersedes` and `Superseded-by` lines, then
`Context`, `Decision` and `Consequences`.

A record is never edited into a different decision. To change one, add a new
record and mark the old one `Superseded`.

| Record | Status |
|---|---|
| [0001. Revoke every session and API credential on password recovery](0001-password-recovery-revokes-sessions-and-api-tokens.md) | Accepted |
