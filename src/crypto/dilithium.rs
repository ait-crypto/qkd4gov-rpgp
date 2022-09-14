//! Dilithium support
//!
//! This module provides support for the Dilithium signature scheme. Currently,
//! this module only provides support for Dilithium-5.

use std::fmt;
use std::ops::Deref;

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroize;

use crate::errors::{Error, Result};
use crate::types::Mpi;

use super::pq_helpers::from_mpis;

/// This marker is used to prevent [Mpi] from stripping leading zero bits.
const MARKER: u8 = 0xff;
/// Maximum number of bytes to encode per [Mpi] value.
const MAX_SIZE: usize = crate::types::MAX_EXTERN_MPI_BITS as usize / 8 - 1;
/// Number of [Mpi] values required to represent a signature.
pub(crate) const NUM_MPIS: usize = (dilithium5::signature_bytes() + MAX_SIZE - 1) / MAX_SIZE;

pub const SECRET_KEY_SIZE: usize = dilithium5::secret_key_bytes();
pub const PUBLIC_KEY_SIZE: usize = dilithium5::public_key_bytes();

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct DilithiumPublicKey {
    pk: dilithium5::PublicKey,
}

impl Eq for DilithiumPublicKey {}

impl From<dilithium5::PublicKey> for DilithiumPublicKey {
    #[inline]
    fn from(pk: dilithium5::PublicKey) -> Self {
        Self { pk }
    }
}

impl Deref for DilithiumPublicKey {
    type Target = dilithium5::PublicKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.pk
    }
}

impl AsRef<[u8]> for DilithiumPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.pk.as_bytes()
    }
}

impl TryFrom<&[u8]> for DilithiumPublicKey {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        dilithium5::PublicKey::from_bytes(value)
            .map(Self::from)
            .map_err(|_| Error::Message("Dilithium key deserialization failed".to_owned()))
    }
}

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct DilithiumSecretKey {
    sk: dilithium5::SecretKey,
}

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumSK").field("sk", &"[..]").finish()
    }
}

impl Eq for DilithiumSecretKey {}

impl Zeroize for DilithiumSecretKey {
    fn zeroize(&mut self) {
        // FIXME
        // self.sk.zeroize()
    }
}

impl From<dilithium5::SecretKey> for DilithiumSecretKey {
    #[inline]
    fn from(sk: dilithium5::SecretKey) -> Self {
        Self { sk }
    }
}

impl Deref for DilithiumSecretKey {
    type Target = dilithium5::SecretKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

impl AsRef<[u8]> for DilithiumSecretKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.sk.as_bytes()
    }
}

impl TryFrom<&[u8]> for DilithiumSecretKey {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        dilithium5::SecretKey::from_bytes(value)
            .map(Self::from)
            .map_err(|_| Error::Message("Dilithium key deserialization failed".to_owned()))
    }
}

/// Generate a KeyPair.
pub fn generate_key() -> (DilithiumPublicKey, DilithiumSecretKey) {
    let (public, secret) = dilithium5::keypair();
    (public.into(), secret.into())
}

/// Verify using Dilithium.
pub fn verify(pk: &DilithiumPublicKey, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
    // reconstruct signature from multiple Mpis
    let signature = from_mpis(sig)?;
    dilithium5::verify_detached_signature(
        &DetachedSignature::from_bytes(signature.as_ref())
            .map_err(|_| "Dilithium signature deserialization failed".to_owned())?,
        hashed,
        pk,
    )
    .map_err(|_| Error::Message("Dilithium signature verification failed".to_owned()))
}

// Sign using Dilithium.
pub fn sign(secret_key: &DilithiumSecretKey, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    let signature = dilithium5::detached_sign(digest, secret_key);

    let mut result: Vec<Vec<u8>> = signature
        .as_bytes()
        .chunks(MAX_SIZE)
        .map(|slice| {
            let mut v = Vec::with_capacity(slice.len() + 1);
            v.push(MARKER);
            v.extend_from_slice(slice);
            v
        })
        .collect();

    assert_eq!(result.len(), NUM_MPIS);

    // fill up the signature with empty Mpis so that we always have exactly NUM_MPIS Mpis stored in the vector
    while result.len() < NUM_MPIS {
        result.push(Vec::new())
    }
    Ok(result)
}
