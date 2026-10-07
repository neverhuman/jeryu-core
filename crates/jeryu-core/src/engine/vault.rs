//! Envelope encryption for provider secrets.
//!
//! Each sealed secret gets a fresh 256-bit data key. The secret is encrypted
//! with AES-256-GCM under that data key; the data key is encrypted under the
//! deployment vault key. Both encryptions bind the same associated data
//! (connection, owner, provider, generation, secret version), so a sealed
//! value copied onto another row, or replayed after a rotation, fails to open.

use std::io::Read;
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
        use rustix::fs::{FileType, Mode, OFlags};
        let unavailable = || {
            ForgeError::Validation(
                "vault_key_unavailable: the vault key file is missing or unreadable".into(),
            )
        };
        // Open without following a symlink and check the descriptor we read,
        // so the file cannot be swapped between the check and the read.
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(|_| unavailable())?;
        let stat = rustix::fs::fstat(&fd).map_err(|_| unavailable())?;
        let regular = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile;
        if !regular
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o077 != 0
        {
            return Err(ForgeError::Validation(
                "vault_key_custody_denied: the vault key file must be a private regular file owned by this service".into(),
            ));
        }
        let mut raw = Zeroizing::new(Vec::with_capacity(128));
        std::fs::File::from(fd)
            .take(256)
            .read_to_end(&mut raw)
            .map_err(|_| unavailable())?;
        let trimmed = raw.trim_ascii();
        if trimmed.len() == KEY_BYTES * 2 {
            let decoded = hex::decode(trimmed).map_err(|_| {
                ForgeError::Validation(
                    "vault_key_invalid: the vault key file is neither 64 hex characters nor 32 raw bytes".into(),
                )
            })?;
            return Self::from_bytes(&Zeroizing::new(decoded));
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
        let data_key = decrypt(&self.key, &aad, &sealed.key_nonce, &sealed.wrapped_key)?;
        decrypt(
            &key_from(&data_key)?,
            &aad,
            &sealed.nonce,
            &sealed.ciphertext,
        )
    }
}

/// The row identity a sealed secret is bound to.
pub(crate) struct SealBinding<'a> {
    pub(crate) connection_id: &'a str,
    pub(crate) owner_id: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) generation: u64,
    /// Refresh rotations within the generation: a value sealed at version N
    /// does not open once the row says N+1 (connection-v1 §3).
    pub(crate) secret_version: u64,
    /// Binding the kind stops a database writer from turning an API key into
    /// a "refresh token" that would be sent to a token endpoint.
    pub(crate) credential_kind: &'a str,
}

impl SealBinding<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut aad = AAD_DOMAIN.to_vec();
        for part in [
            self.connection_id,
            self.owner_id,
            self.provider,
            self.credential_kind,
        ] {
            aad.extend_from_slice(part.as_bytes());
            aad.push(0);
        }
        aad.extend_from_slice(&self.generation.to_be_bytes());
        aad.extend_from_slice(&self.secret_version.to_be_bytes());
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
    // Sized for the tag up front so appending it never reallocates and
    // leaves a plaintext copy behind in freed memory.
    let mut sealed = Zeroizing::new(Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len()));
    sealed.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut *sealed,
    )
    .map_err(|_| vault_failure())?;
    Ok((nonce, sealed.to_vec()))
}

fn decrypt(
    key: &LessSafeKey,
    aad: &[u8],
    nonce_hex: &str,
    sealed_hex: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let tampered = || {
        ForgeError::Validation(
            "vault_secret_unreadable: the sealed secret failed authentication".into(),
        )
    };
    let nonce: [u8; NONCE_LEN] = hex::decode(nonce_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(tampered)?;
    let mut sealed = Zeroizing::new(hex::decode(sealed_hex).map_err(|_| tampered())?);
    let plain_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut sealed,
        )
        .map_err(|_| tampered())?
        .len();
    // The plaintext is the buffer's prefix; drop the tag in place.
    sealed.truncate(plain_len);
    Ok(sealed)
}

fn vault_failure() -> ForgeError {
    ForgeError::Storage("vault_crypto_failed: the vault could not seal or open a secret".into())
}
