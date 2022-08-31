//! Picnic support
//!
//! This module provides support for the Picnic signature scheme. Currently,
//! this module only provides support for PicnicL5-FS.

use picnic_bindings::PicnicL5FSVerificationKey;
use picnic_bindings::{signature::Signer, Parameters, PicnicL5FSSigningKey, RawVerifier};

use crate::errors::{Error, Result};
use crate::types::Mpi;

use super::pq_helpers::{from_mpis, MARKER, MAX_SIZE};

/// Number of [Mpi] values required to represent a signature.
pub(crate) const NUM_MPIS: usize =
    (picnic_bindings::PicnicL5FS::MAX_SIGNATURE_SIZE + MAX_SIZE - 1) / MAX_SIZE;

pub const SECRET_KEY_SIZE: usize = picnic_bindings::PicnicL5FS::PRIVATE_KEY_SIZE;
pub const PUBLIC_KEY_SIZE: usize = picnic_bindings::PicnicL5FS::PUBLIC_KEY_SIZE;

pub type PicnicPublicKey = PicnicL5FSVerificationKey;
pub type PicnicSecretKey = PicnicL5FSSigningKey;

/// Generate a Picnic KeyPair.
pub fn generate_key() -> (PicnicPublicKey, PicnicSecretKey) {
    let (secret, public) = PicnicL5FSSigningKey::random().expect("Picnic L5 FS not supported!");
    (public, secret)
}

/// Verify a Picnic signature.
pub fn verify(pk: &PicnicPublicKey, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
    // reconstruct signature from multiple Mpis
    let signature = from_mpis(sig)?;

    pk.verify_raw(hashed, signature.as_ref())
        .map_err(|_| Error::Message("Picnic signature verification failed".to_owned()))
}

/// Sign using Picnic.
pub fn sign(sk: &PicnicSecretKey, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    let signature = sk.sign(digest);

    let mut result: Vec<Vec<u8>> = signature
        .as_ref()
        .chunks(MAX_SIZE)
        .map(|slice| {
            let mut v = Vec::with_capacity(slice.len() + 1);
            v.push(MARKER);
            v.extend_from_slice(slice);
            v
        })
        .collect();

    // fill up the signature with empty Mpis so that we always have exactly NUM_MPIS Mpis stored in the vector
    while result.len() < NUM_MPIS {
        result.push(Vec::new())
    }
    Ok(result)
}
