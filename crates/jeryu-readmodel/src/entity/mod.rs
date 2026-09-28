//! Unified entity model for the read-model contract.
//!
//! Every TUI/web-rendered object maps to exactly one [`EntityKind`]; entity IDs
//! are globally unique within a kind. Provider-neutral: no SCM-vendor names.

mod kind;
mod refs;
mod support;

pub use kind::EntityKind;
pub use refs::{EntityRef, HealthLevel, Severity};
pub use support::{
    ActionRef, BlockerSummary, Bug, BugAttempt, DataFreshness, EntityDetail, EvidenceRef, Project,
    TimelineEvent,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_ref_display_uses_label() {
        let r = EntityRef::new(EntityKind::Job, "14445");
        assert_eq!(r.display(), "job:14445");
        assert_eq!(format!("{r}"), "job:14445");
    }

    #[test]
    fn pull_request_kind_is_provider_neutral() {
        assert_eq!(EntityKind::PullRequest.label(), "pr");
        assert_eq!(EntityKind::PullRequest.badge(), "PR");
        assert_eq!(EntityKind::PullRequest.route_segment(), "pull-requests");
    }

    #[test]
    fn all_entity_kinds_have_distinct_serde_tags() {
        // Every kind must round-trip through serde and ALL must be exhaustive.
        for kind in EntityKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: EntityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn entity_kind_labels_and_route_segments_are_unique() {
        // Labels key entity refs and route segments build URLs, so two kinds
        // sharing either would alias distinct entities.
        let mut labels = std::collections::HashSet::new();
        let mut routes = std::collections::HashSet::new();
        for kind in EntityKind::ALL {
            assert!(labels.insert(kind.label()), "duplicate label {kind:?}");
            assert!(
                routes.insert(kind.route_segment()),
                "duplicate route {kind:?}"
            );
            assert!(!kind.badge().is_empty(), "empty badge {kind:?}");
        }
    }

    #[test]
    fn severity_orders_critical_first() {
        assert!(Severity::Critical < Severity::Error);
        assert!(Severity::Error < Severity::Warning);
        assert!(Severity::Warning < Severity::Info);
    }
}
