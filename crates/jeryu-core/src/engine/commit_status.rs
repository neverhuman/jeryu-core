//! Commit statuses and combined status rollups.

use std::collections::BTreeMap;

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use super::{ForgeCore, emit_event_locked, refresh_pull_mergeability_for_sha, require_name};
use crate::errors::Result;
use crate::model::*;
use crate::webhooks::event_payload;

impl ForgeCore {
    pub fn create_commit_status(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        creator: &str,
        request: CreateCommitStatusRequest,
    ) -> Result<CommitStatus> {
        require_name("sha", sha)?;
        self.ensure_repository_writable(owner, repo)?;
        self.ensure_user(creator);
        let now = Utc::now();
        let status = CommitStatus {
            id: Uuid::new_v4(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            sha: sha.to_string(),
            state: request.state,
            context: request.context,
            description: request.description,
            target_url: request.target_url,
            creator: creator.to_string(),
            created_at: now,
            updated_at: now,
        };
        let mut state = self.state.write();
        let previous = state.clone();
        state
            .statuses
            .entry((owner.to_string(), repo.to_string(), sha.to_string()))
            .or_default()
            .push(status.clone());
        refresh_pull_mergeability_for_sha(&mut state, owner, repo, sha);
        emit_event_locked(
            &mut state,
            owner,
            repo,
            "status",
            event_payload("created", "status", json!(status.clone())),
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(status)
    }

    pub fn combined_status(&self, owner: &str, repo: &str, sha: &str) -> Result<CombinedStatus> {
        self.ensure_repo_exists(owner, repo)?;
        // No status entry for the sha means no statuses have been posted; an
        // empty list is the intended value (and is itself reported as Pending).
        let statuses = match self.state.read().statuses.get(&(
            owner.to_string(),
            repo.to_string(),
            sha.to_string(),
        )) {
            Some(statuses) => statuses.clone(),
            None => Vec::new(),
        };
        // Keep the append-only history in the response, but aggregate one current
        // row per context, just as branch protection does. Equal timestamps pick
        // the later appended row; SQLite restores this order using cs.rowid.
        let mut current = BTreeMap::<&str, &CommitStatus>::new();
        for status in &statuses {
            let entry = current.entry(&status.context).or_insert(status);
            if status.updated_at >= entry.updated_at {
                *entry = status;
            }
        }
        let state = if current
            .values()
            .any(|status| status.state == CommitStatusState::Error)
        {
            CommitStatusState::Error
        } else if current
            .values()
            .any(|status| status.state == CommitStatusState::Failure)
        {
            CommitStatusState::Failure
        } else if current.is_empty()
            || current
                .values()
                .any(|status| status.state == CommitStatusState::Pending)
        {
            CommitStatusState::Pending
        } else {
            CommitStatusState::Success
        };
        Ok(CombinedStatus {
            state,
            total_count: statuses.len(),
            statuses,
        })
    }
}
