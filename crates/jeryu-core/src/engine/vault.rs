//! Envelope encryption for provider secrets.
//!
//! Each sealed secret gets a fresh 256-bit data key. The secret is encrypted
//! with AES-256-GCM under that data key; the data key is encrypted under the
//! deployment vault key. Both encryptions bind the same associated data
//! (connection, owner, provider, generation), so a sealed value copied onto
//! another row, or replayed into a later generation, fails to open.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::{ForgeError, Result};

const AAD_DOMAIN: &[u8] = b"jeryu.vault.provider-secret.v1\0";
const KEY_BYTES: usize = 32;

/// The deployment's vault key (key-encryption key). Loaded once at startup.
pub struct VaultKey {
    id: String,
    key: LessSafeKey,
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A sealed secret as stored: hex fields, no plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedSecret {
    pub(crate) key_id: String,
    pub(crate) key_nonce: String,
    pub(crate) wrapped_key: String,
    pub(crate) nonce: String,
    pub(crate) ciphertext: String,
}

impl VaultKey {
    /// Use 32 raw key bytes. Callers own where the bytes come from.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_BYTES {
            return Err(ForgeError::Validation(
                "vault_key_invalid: the vault key must be exactly 32 bytes".into(),
            ));
        }
        let id = format!("vk-{}", &hex::encode(Sha256::digest(bytes))[..16]);
        let key = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| vault_failure())?;
        Ok(Self {
            id,
            key: LessSafeKey::new(key),
        })
    }

    /// Load the key from a file holding 32 raw bytes or 64 hex characters.
    /// The file must be a regular file owned by this process's user and not
    /// readable or writable by group or others.
    pub fn from_file(path: &Path) -> Result<Self> {
        let unavailable = || {
            ForgeError::Validation(
                "vault_key_unavailable: the vault key file is missing or unreadable".into(),
            )
        };
        let meta = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        // `/proc/self` is owned by this process's effective uid, which gives
        // the ownership check without an unsafe `geteuid` call.
        let self_uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .map_err(|_| unavailable())?;
        if !meta.is_file() || meta.uid() != self_uid || meta.mode() & 0o077 != 0 {
            return Err(ForgeError::Validation(
                "vault_key_custody_denied: the vault key file must be a private regular file owned by this service".into(),
            ));
        }
        let raw = Zeroizing::new(std::fs::read(path).map_err(|_| unavailable())?);
        let trimmed = raw.trim_ascii();
        if trimmed.len() == KEY_BYTES * 2 {
            let decoded = Zeroizing::new(hex::decode(trimmed).map_err(|_| unavailable())?);
            return Self::from_bytes(&decoded);
        }
        Self::from_bytes(&raw)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn seal(&self, binding: &SealBinding<'_>, secret: &[u8]) -> Result<SealedSecret> {
        let rng = SystemRandom::new();
        let mut data_key = Zeroizing::new([0_u8; KEY_BYTES]);
        rng.fill(data_key.as_mut()).map_err(|_| vault_failure())?;
        let aad = binding.aad();
        let (nonce, ciphertext) = encrypt(&key_from(&data_key[..])?, &aad, secret, &rng)?;
        let (key_nonce, wrapped_key) = encrypt(&self.key, &aad, &data_key[..], &rng)?;
        Ok(SealedSecret {
            key_id: self.id.clone(),
            key_nonce: hex::encode(key_nonce),
            wrapped_key: hex::encode(wrapped_key),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }

    pub(crate) fn open(
        &self,
        binding: &SealBinding<'_>,
        sealed: &SealedSecret,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.key_id != self.id {
            return Err(ForgeError::Validation(
                "vault_key_mismatch: the secret was sealed under a different vault key".into(),
            ));
        }
        let aad = binding.aad();
        let data_key = Zeroizing::new(decrypt(
            &self.key,
            &aad,
            &sealed.key_nonce,
            &sealed.wrapped_key,
        )?);
        decrypt(
            &key_from(&data_key)?,
            &aad,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .map(Zeroizing::new)
    }
}

/// The row identity a sealed secret is bound to.
pub(crate) struct SealBinding<'a> {
    pub(crate) connection_id: &'a str,
    pub(crate) owner_id: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) generation: u64,
}

impl SealBinding<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut aad = AAD_DOMAIN.to_vec();
        for part in [self.connection_id, self.owner_id, self.provider] {
            aad.extend_from_slice(part.as_bytes());
            aad.push(0);
        }
        aad.extend_from_slice(&self.generation.to_be_bytes());
        aad
    }
}

fn key_from(bytes: &[u8]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| vault_failure())
}

fn encrypt(
    key: &LessSafeKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &SystemRandom,
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| vault_failure())?;
    let mut sealed = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut sealed,
    )
    .map_err(|_| vault_failure())?;
    Ok((nonce, sealed))
}

fn decrypt(key: &LessSafeKey, aad: &[u8], nonce_hex: &str, sealed_hex: &str) -> Result<Vec<u8>> {
    let tampered = || {
        ForgeError::Validation(
            "vault_secret_unreadable: the sealed secret failed authentication".into(),
        )
    };
    let nonce: [u8; NONCE_LEN] = hex::decode(nonce_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(tampered)?;
    let mut sealed = hex::decode(sealed_hex).map_err(|_| tampered())?;
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut sealed,
        )
        .map_err(|_| tampered())?;
    Ok(plaintext.to_vec())
}

fn vault_failure() -> ForgeError {
    ForgeError::Storage("vault_crypto_failed: the vault could not seal or open a secret".into())
}
