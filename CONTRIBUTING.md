# Contributing

## Pull requests

Outside pull requests are welcome on GitHub. This repository is a read-only
mirror of the forge, where contributions are gated, reviewed, and merged.
Until the importer is live, GitHub pull requests are read but are not merged yet.
Once imported contributions merge on the forge, the mirror receives the changes
and the GitHub pull request is closed with a link to the forge result.

## Tests and fixtures

Use invented data in all tests and fixtures, such as acme, globex, and
`service.example`. Never include real site or personal data.

## Local gate

Run from the repository root with the repository's Rust toolchain installed:

```sh
set -e
JERYU_SPLIT_FULL_CHECK=1 ./ops/ci/check.sh
cargo test --offline -p jeryu-core -p jeryu-readmodel -p jeryu-gitd
```

The offline tests require dependencies to be available locally; the full check
can populate the dependency cache on the first run.
