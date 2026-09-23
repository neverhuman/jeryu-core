//! Web edge bootstrap, viewer, feature-flag, and live-stream (WebSocket)
//! contracts consumed by the SPA shell and the activity stream.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::repository::RepositorySummary;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Viewer {
    pub id: String,
    pub login: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// Normalized permission keys (24-key set per §35.1.18).
    pub global_permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebFeatureFlags {
    pub repo_create: bool,
    pub settings_write: bool,
    pub merge_write: bool,
    pub markdown_html: bool,
    pub agents: bool,
    pub mcp: bool,
    pub workcells: bool,
}

/// Canonical path of the TUI read model (`crate::read_model::TuiReadModel`).
///
/// It is a resource of its own, not a representation of bootstrap: clients
/// fetch it when they need it instead of receiving it inside every bootstrap.
pub const TUI_READ_MODEL_PATH: &str = "/api/v1/read-model/tui";

/// Where a client fetches the read models bootstrap points at but does not
/// carry. Bootstrap stays small (viewer, versions, links); each read model is
/// fetched by the clients that project it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebBootstrapLinks {
    /// [`TUI_READ_MODEL_PATH`] — the TUI read model as its own resource.
    pub tui_read_model: String,
}

impl Default for WebBootstrapLinks {
    fn default() -> Self {
        Self {
            tui_read_model: TUI_READ_MODEL_PATH.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebBootstrap {
    pub generated_at: String,
    pub schema_version: String,
    pub viewer: Viewer,
    /// Where the read models live. Bootstrap used to embed the whole TUI read
    /// model, which made it a second copy of that resource; it now names it.
    pub links: WebBootstrapLinks,
    pub recent_repositories: Vec<RepositorySummary>,
    pub websocket_url: String,
    pub feature_flags: WebFeatureFlags,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebEvent {
    pub seq: u64,
    pub timestamp: String,
    pub scope: String,
    pub kind: String,
    pub entity: String,
    pub summary: String,
    /// Free-form payload carrying severity, parent, evidence refs, etc.
    #[ts(type = "Record<string, unknown>")]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubscriptionSpec {
    /// Granular topic per §35.1.15, e.g. `global.activity`, `repo.{id}`,
    /// `pr.{id}`, `agent.{id}`, `cache.{id}`. Backend re-checks each scope
    /// against the viewer's perms on every `Subscribe` frame (§35.1.6).
    pub scope: String,
    /// Free-form filter object (e.g. `{ kind: ["pr.approved"] }`).
    #[ts(type = "Record<string, unknown>")]
    pub filters: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientWsMessage {
    Hello {
        resume_from: Option<u64>,
        subscriptions: Vec<SubscriptionSpec>,
    },
    Subscribe {
        subscriptions: Vec<SubscriptionSpec>,
    },
    Unsubscribe {
        scopes: Vec<String>,
    },
    Ack {
        seq: u64,
    },
    Ping {
        nonce: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerWsMessage {
    Hello {
        server_time: String,
        current_seq: u64,
        protocol: String,
    },
    SnapshotRequired {
        reason: String,
        current_seq: u64,
    },
    Event {
        event: WebEvent,
    },
    Pong {
        nonce: String,
        server_time: String,
    },
    Error {
        code: String,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap() -> WebBootstrap {
        WebBootstrap {
            generated_at: "2026-09-23T00:00:00Z".to_string(),
            schema_version: "0.1.0-alpha".to_string(),
            viewer: Viewer {
                id: "local".to_string(),
                login: "local".to_string(),
                display_name: None,
                avatar_url: None,
                global_permissions: vec!["repo:read".to_string()],
            },
            links: WebBootstrapLinks::default(),
            recent_repositories: Vec::new(),
            websocket_url: "/api/v1/ws".to_string(),
            feature_flags: WebFeatureFlags {
                repo_create: false,
                settings_write: false,
                merge_write: false,
                markdown_html: false,
                agents: false,
                mcp: false,
                workcells: false,
            },
        }
    }

    #[test]
    fn bootstrap_names_the_read_model_instead_of_carrying_it() {
        let json = serde_json::to_value(bootstrap()).expect("serialize");
        let object = json.as_object().expect("bootstrap is an object");
        assert!(
            !object.contains_key("tui"),
            "bootstrap must link to the read model, not embed a copy of it"
        );
        assert_eq!(
            object["links"]["tui_read_model"],
            serde_json::json!(TUI_READ_MODEL_PATH)
        );
    }

    #[test]
    fn bootstrap_stays_small() {
        let encoded = serde_json::to_string(&bootstrap()).expect("serialize");
        assert!(
            encoded.len() < 1024,
            "bootstrap grew to {} bytes; it carries viewer, versions and links only",
            encoded.len()
        );
    }

    #[test]
    fn bootstrap_round_trips_json() {
        let original = bootstrap();
        let encoded = serde_json::to_string(&original).expect("serialize");
        let decoded: WebBootstrap = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, original);
    }
}
