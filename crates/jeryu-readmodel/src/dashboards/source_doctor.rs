//! Source Doctor dashboard contract.
//! Pure data; freshness carried alongside; default = "empty/unavailable".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::freshness::{SourceFreshness, SourceKind};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SourceDoctorDashboard {
    pub items: Vec<SourceDoctorItem>,
    pub freshness: Option<SourceFreshness>,
    pub summary: Option<SourceDoctorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceDoctorItem {
    pub id: String,
    pub label: String,
    pub source_kind: SourceKind,
    pub state: String,
    pub last_error: Option<String>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub drift_kind: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SourceDoctorSummary {
    pub sources_total: u32,
    pub sources_healthy: u32,
    pub sources_degraded: u32,
    pub schema_drift_count: u32,
}
