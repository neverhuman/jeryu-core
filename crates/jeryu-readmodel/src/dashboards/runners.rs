//! Runners dashboard contract.
//! Pure data; freshness carried alongside; default = "empty/unavailable".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::HealthLevel;
use crate::freshness::SourceFreshness;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RunnersDashboard {
    pub items: Vec<RunnersItem>,
    pub freshness: Option<SourceFreshness>,
    pub summary: Option<RunnersSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunnersItem {
    pub id: String,
    pub label: String,
    pub runner_id: String,
    pub pool: String,
    pub status: HealthLevel,
    pub tags: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RunnersSummary {
    pub total_runners: u32,
    pub active_runners: u32,
    pub paused_runners: u32,
    pub draining_runners: u32,
}
