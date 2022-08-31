//! Picnic support
//!
//! This module provides support for the Picnic signature scheme. Currently,
//! this module only provides support for PicnicL5-FS.

use std::convert::TryFrom;

use picnic_bindings::{
    signature::Signer, Parameters, PicnicL5FSSigningKey, PicnicL5FSVerificationKey, RawVerifier,
};

use crate::errors::{Error, Result};
use crate::types::{Mpi, PicnicSecretKey, PlainSecretParams, PublicParams};

use super::pq_helpers::{as_mpi, from_mpis, MARKER, MAX_SIZE};

/// Number of [Mpi] values required to represent a signature.
pub(crate) const NUM_MPIS: usize =
    (picnic_bindings::PicnicL5FS::MAX_SIGNATURE_SIZE + MAX_SIZE - 1) / MAX_SIZE;

/// Generate a Picnic KeyPair.
pub fn generate_key() -> (PublicParams, PlainSecretParams) {
    let (secret, public) = PicnicL5FSSigningKey::random().expect("Picnic L5 FS not supported!");

    // public key
    let pk = as_mpi(&public);
    // secret key
    let sk = as_mpi(&secret);

    (PublicParams::Picnic { pk }, PlainSecretParams::Picnic(sk))
}

/// Verify a Picnic signature.
pub fn verify(pk: &[u8], hashed: &[u8], sig: &[Mpi]) -> Result<()> {
    if pk.is_empty() || pk[0] != MARKER {
        return Err(Error::InvalidKeyLength);
    }
    let pk = PicnicL5FSVerificationKey::try_from(&pk[1..])?;

    // reconstruct signature from multiple Mpis
    let signature = from_mpis(sig)?;

    pk.verify_raw(hashed, signature.as_ref())
        .map_err(|_| Error::Message("Picnic signature verification failed".to_owned()))
}

/// Sign using Picnic.
pub fn sign(secret_key: &PicnicSecretKey, digest: &[u8]) -> Result<Vec<Vec<u8>>> {
    if secret_key.secret.is_empty() || secret_key.secret[0] != MARKER {
        return Err(Error::InvalidKeyLength);
    }

    let sk = PicnicL5FSSigningKey::try_from(&secret_key.secret[1..])?;
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
