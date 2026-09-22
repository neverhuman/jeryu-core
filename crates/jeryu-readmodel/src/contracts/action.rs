//! Inline available-action DTO shared by web summary contracts.
//!
//! Summaries advertise the actions the viewer may take (`available_actions`)
//! as an inline array of `{ action_id, label, risk, method, href }`. `method`
//! and `href` name the HTTP route that performs the action, so a client that
//! sees an action can invoke it without a separate lookup table. It is emitted
//! inline at each use site via a `#[ts(type = …)]` override, so this struct is
//! a real Rust source type without needing its own exported binding.

use serde::{Deserialize, Serialize};

/// One viewer-affordable action surfaced on a summary contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableAction {
    pub action_id: String,
    pub label: String,
    pub risk: Option<String>,
    /// HTTP method of the route that performs the action (`POST`, `DELETE`, …).
    /// `None` for navigation-only actions and for payloads written before the
    /// field existed.
    #[serde(default)]
    pub method: Option<String>,
    /// Path of the route that performs the action, e.g.
    /// `/api/web/repos/acme/app/pulls/7/merge`.
    #[serde(default)]
    pub href: Option<String>,
}

impl AvailableAction {
    /// Action without an invocation route yet; attach one with [`Self::route`].
    pub fn new(action_id: impl Into<String>, label: impl Into<String>, risk: Option<&str>) -> Self {
        Self {
            action_id: action_id.into(),
            label: label.into(),
            risk: risk.map(str::to_string),
            method: None,
            href: None,
        }
    }

    /// Point the action at the route and method that performs it.
    pub fn route(mut self, method: impl Into<String>, href: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self.href = Some(href.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_action_serializes_method_and_href() {
        let action = AvailableAction::new("pull.merge", "Merge", Some("medium"))
            .route("POST", "/api/web/repos/acme/app/pulls/7/merge");
        let value = serde_json::to_value(&action).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["href"], "/api/web/repos/acme/app/pulls/7/merge");
    }

    #[test]
    fn payload_without_route_fields_still_deserializes() {
        let action: AvailableAction =
            serde_json::from_str(r#"{"action_id":"repo.open","label":"Open","risk":null}"#).unwrap();
        assert_eq!(action, AvailableAction::new("repo.open", "Open", None));
    }
}
