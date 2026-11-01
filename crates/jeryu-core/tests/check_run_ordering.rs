use jeryu_core::{
    CheckConclusion, CheckRun, CheckRunStatus, CreateCheckRunRequest, CreateRepositoryRequest,
    ForgeCore,
};
use rusqlite::Connection;

fn request(conclusion: Option<CheckConclusion>) -> CreateCheckRunRequest {
    CreateCheckRunRequest {
        name: "jankurai/proof".to_string(),
        head_sha: "abc123".to_string(),
        status: Some(if conclusion.is_some() {
            CheckRunStatus::Completed
        } else {
            CheckRunStatus::Queued
        }),
        conclusion,
        details_url: None,
        output: None,
    }
}

fn open_with_repo(db: &std::path::Path) -> ForgeCore {
    let core = ForgeCore::open_sqlite(db).unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "jeryu".to_string(),
            private: true,
            description: None,
            default_branch: None,
        },
    )
    .unwrap();
    core
}

fn runs(core: &ForgeCore) -> Vec<CheckRun> {
    core.list_check_runs("alice", "jeryu", Some("abc123"))
        .unwrap()
        .check_runs
}

#[test]
fn creation_sequence_is_monotonic_and_survives_reload() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let expected: Vec<(uuid::Uuid, u64)> = {
        let core = open_with_repo(&db);
        // Created back to back, so timestamps may tie.
        for conclusion in [
            Some(CheckConclusion::Failure),
            None,
            Some(CheckConclusion::Success),
        ] {
            core.create_check_run("alice", "jeryu", request(conclusion))
                .unwrap();
        }
        let created = runs(&core);
        let sequences: Vec<u64> = created.iter().map(|run| run.creation_sequence).collect();
        assert_eq!(sequences, [1, 2, 3]);
        created
            .iter()
            .map(|run| (run.id, run.creation_sequence))
            .collect()
    };
    let reopened = ForgeCore::open_sqlite(&db).unwrap();
    let after: Vec<(uuid::Uuid, u64)> = runs(&reopened)
        .iter()
        .map(|run| (run.id, run.creation_sequence))
        .collect();
    assert_eq!(after, expected);
    let newest = CheckRun::newest(&runs(&reopened)).map(|run| run.creation_sequence);
    assert_eq!(newest, Some(3));
    // A later run keeps counting from the reloaded maximum.
    let next = reopened
        .create_check_run("alice", "jeryu", request(None))
        .unwrap();
    assert_eq!(next.creation_sequence, 4);
}

#[test]
fn rows_without_a_stored_sequence_are_numbered_in_insertion_order() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let ids: Vec<uuid::Uuid> = {
        let core = open_with_repo(&db);
        for _ in 0..3 {
            core.create_check_run("alice", "jeryu", request(Some(CheckConclusion::Success)))
                .unwrap();
        }
        runs(&core).iter().map(|run| run.id).collect()
    };
    Connection::open(&db)
        .unwrap()
        .execute("UPDATE check_runs SET creation_sequence = 0", [])
        .unwrap();
    let reopened = ForgeCore::open_sqlite(&db).unwrap();
    let numbered: Vec<(uuid::Uuid, u64)> = runs(&reopened)
        .iter()
        .map(|run| (run.id, run.creation_sequence))
        .collect();
    assert_eq!(numbered, vec![(ids[0], 1), (ids[1], 2), (ids[2], 3)]);
}

#[test]
fn payload_without_a_sequence_reads_as_zero() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let core = open_with_repo(&db);
    let run = core
        .create_check_run("alice", "jeryu", request(None))
        .unwrap();
    let mut value = serde_json::to_value(&run).unwrap();
    value.as_object_mut().unwrap().remove("creation_sequence");
    let parsed: CheckRun = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.creation_sequence, 0);
}

#[test]
fn mixed_legacy_rows_preserve_stored_ordinals_through_reconciliation() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let ids = {
        let core = open_with_repo(&db);
        for _ in 0..3 {
            core.create_check_run("alice", "jeryu", request(None))
                .unwrap();
        }
        runs(&core).iter().map(|run| run.id).collect::<Vec<_>>()
    };
    let conn = Connection::open(&db).unwrap();
    for (id, sequence) in [(ids[0], 10), (ids[1], 20), (ids[2], 0)] {
        conn.execute(
            "UPDATE check_runs SET creation_sequence=?1 WHERE id=?2",
            rusqlite::params![sequence, id.to_string()],
        )
        .unwrap();
    }
    // Physical row order is not a stored ordinal: a reinserted older row can
    // follow a new legacy row, without acquiring a newer creation identity.
    conn.execute(
        "UPDATE check_runs SET rowid=10000 WHERE id=?1",
        [ids[0].to_string()],
    )
    .unwrap();
    drop(conn);
    let core = ForgeCore::open_sqlite(&db).unwrap();
    let expected = [(ids[0], 10), (ids[1], 20), (ids[2], 21)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let ordinals = |core: &ForgeCore| {
        runs(core)
            .into_iter()
            .map(|run| (run.id, run.creation_sequence))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(ordinals(&core), expected);
    assert_eq!(CheckRun::newest(&runs(&core)).unwrap().id, ids[2]);
    let next = core
        .create_check_run("alice", "jeryu", request(None))
        .unwrap();
    assert_eq!(next.creation_sequence, 22);
    drop(core);
    let reopened = ForgeCore::open_sqlite(&db).unwrap();
    let mut expected = expected;
    expected.insert(next.id, 22);
    assert_eq!(ordinals(&reopened), expected);
}
