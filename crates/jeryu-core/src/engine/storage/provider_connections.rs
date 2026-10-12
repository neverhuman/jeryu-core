//! Provider connections (migration 0018): State-owned rows whose secret column
//! holds only the sealed AES-256-GCM envelope.

use rusqlite::{Connection, params};

use super::codec::{optional_time, parse_optional_time, parse_time, time};
use super::{State, storage_error};
use crate::core::provider_connections::{ConnectionRecord, Rotation};
use crate::errors::{ForgeError, Result};
use crate::model::{AgentProvider, ConnectionState, CredentialKind, ProviderConnection};

pub(super) fn stage_provider_connections(conn: &Connection, state: &State) -> Result<()> {
    for record in state.provider_connections.values() {
        let c = &record.connection;
        let sealed = record
            .sealed
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(storage_error)?;
        conn.execute(
            r#"
            INSERT INTO temp.provider_connections (
              id, owner_id, provider, provider_account, credential_kind, state,
              connection_generation, secret_version, sealed_secret, created_at,
              updated_at, refreshed_at, rotation_secret_version, rotation_started_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                c.id,
                c.owner_id,
                c.provider.as_str(),
                c.provider_account,
                c.credential_kind.as_str(),
                c.state.as_str(),
                i64::try_from(c.connection_generation).map_err(storage_error)?,
                i64::try_from(c.secret_version).map_err(storage_error)?,
                sealed,
                time(c.created_at),
                time(c.updated_at),
                optional_time(c.refreshed_at),
                record
                    .rotation
                    .as_ref()
                    .map(|rotation| i64::try_from(rotation.secret_version))
                    .transpose()
                    .map_err(storage_error)?,
                optional_time(record.rotation.as_ref().map(|rotation| rotation.started_at)),
            ],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn load_provider_connections(conn: &Connection, state: &mut State) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT id, owner_id, provider, provider_account, credential_kind, state, \
             connection_generation, secret_version, sealed_secret, created_at, updated_at, \
             refreshed_at, rotation_secret_version, rotation_started_at \
             FROM provider_connections",
        )
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let generation: i64 = row.get(6).map_err(storage_error)?;
        let secret_version: i64 = row.get(7).map_err(storage_error)?;
        let sealed: Option<String> = row.get(8).map_err(storage_error)?;
        let connection = ProviderConnection {
            id: row.get(0).map_err(storage_error)?,
            owner_id: row.get(1).map_err(storage_error)?,
            provider: AgentProvider::parse(&row.get::<_, String>(2).map_err(storage_error)?)?,
            provider_account: row.get(3).map_err(storage_error)?,
            credential_kind: credential_kind(&row.get::<_, String>(4).map_err(storage_error)?)?,
            state: connection_state(&row.get::<_, String>(5).map_err(storage_error)?)?,
            connection_generation: u64::try_from(generation).map_err(storage_error)?,
            secret_version: u64::try_from(secret_version).map_err(storage_error)?,
            created_at: parse_time(row.get(9).map_err(storage_error)?)?,
            updated_at: parse_time(row.get(10).map_err(storage_error)?)?,
            refreshed_at: parse_optional_time(row.get(11).map_err(storage_error)?)?,
        };
        let sealed = sealed
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(storage_error)?;
        let rotation_version: Option<i64> = row.get(12).map_err(storage_error)?;
        let rotation_started: Option<String> = row.get(13).map_err(storage_error)?;
        let rotation = match (rotation_version, parse_optional_time(rotation_started)?) {
            (Some(version), Some(started_at)) => Some(Rotation {
                secret_version: u64::try_from(version).map_err(storage_error)?,
                started_at,
            }),
            _ => None,
        };
        state.provider_connections.insert(
            connection.id.clone(),
            ConnectionRecord {
                connection,
                sealed,
                rotation,
            },
        );
    }
    Ok(())
}

fn credential_kind(value: &str) -> Result<CredentialKind> {
    match value {
        "oauth_refresh" => Ok(CredentialKind::OauthRefresh),
        "api_key" => Ok(CredentialKind::ApiKey),
        _ => Err(ForgeError::Storage(format!(
            "unknown credential kind {value}"
        ))),
    }
}

fn connection_state(value: &str) -> Result<ConnectionState> {
    match value {
        "pending" => Ok(ConnectionState::Pending),
        "connected" => Ok(ConnectionState::Connected),
        "auth_required" => Ok(ConnectionState::AuthRequired),
        "disconnected" => Ok(ConnectionState::Disconnected),
        _ => Err(ForgeError::Storage(format!(
            "unknown connection state {value}"
        ))),
    }
}
