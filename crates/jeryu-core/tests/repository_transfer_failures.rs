//! Repository-transfer collision and terminal-failure coverage.

use jeryu_core::{CreateRepositoryRequest, ForgeCore, ForgeError, PrepareRepositoryTransfer};
use serde_json::json;

fn create_repo(core: &ForgeCore, owner: &str, name: &str) -> uuid::Uuid {
    core.create_repository(
        owner,
        CreateRepositoryRequest {
            name: name.to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap()
    .id
}

fn transfer(repository_id: uuid::Uuid, name: &str) -> PrepareRepositoryTransfer {
    PrepareRepositoryTransfer {
        repository_id,
        expected_source_owner: "jeryu".to_string(),
        expected_source_name: name.to_string(),
        destination_owner: "veox".to_string(),
        request_fingerprint: format!("sha256:{name}"),
        idempotency_key: format!("{name}-to-veox-1"),
    }
}

#[test]
fn transfer_rejects_destination_collision_and_records_failure() {
    let core = ForgeCore::new();
    let repository_id = create_repo(&core, "jeryu", "redline");
    create_repo(&core, "veox", "redline");
    assert!(matches!(
        core.prepare_repository_transfer(transfer(repository_id, "redline")),
        Err(ForgeError::Conflict(_))
    ));

    let other = create_repo(&core, "jeryu", "redline-core");
    let prepared = core
        .prepare_repository_transfer(transfer(other, "redline-core"))
        .unwrap();
    let failed = core
        .fail_repository_transfer(prepared.transaction_id, "storage rename failed")
        .unwrap();
    assert_eq!(failed.failure.as_deref(), Some("storage rename failed"));
    assert!(matches!(
        core.commit_repository_transfer(prepared.transaction_id, json!({})),
        Err(ForgeError::Conflict(_))
    ));
}

#[test]
fn commit_rechecks_destination_without_losing_either_repository() {
    let core = ForgeCore::new();
    let source = create_repo(&core, "jeryu", "redline");
    let prepared = core
        .prepare_repository_transfer(transfer(source, "redline"))
        .unwrap();
    let destination = create_repo(&core, "veox", "redline");

    assert!(matches!(
        core.commit_repository_transfer(prepared.transaction_id, json!({})),
        Err(ForgeError::Conflict(_))
    ));
    assert_eq!(core.get_repository("jeryu", "redline").unwrap().id, source);
    assert_eq!(
        core.get_repository("veox", "redline").unwrap().id,
        destination
    );
    assert_eq!(
        core.get_repository_transfer("redline-to-veox-1")
            .unwrap()
            .status,
        jeryu_core::RepositoryTransferStatus::Prepared
    );
}
