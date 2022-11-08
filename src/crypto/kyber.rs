use std::fmt;
use std::ops::Deref;

use block_padding::{Padding, Pkcs7};
use digest::Digest;
use generic_array::{typenum::U8, GenericArray};
use zeroize::Zeroize;

use crate::crypto::pq_helpers::{as_mpi, from_mpi};
use crate::crypto::{aes_kw, HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use crate::errors::{Error, Result};
use crate::types::Mpi;

use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: &[u8; 20] = b"Anonymous Sender    ";

const OID: &[u8] = b"Kyber OID not yet specified";
const HASH: HashAlgorithm = HashAlgorithm::SHA3_512;
const CIPHER: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

pub const SECRET_KEY_SIZE: usize = kyber512::secret_key_bytes();
pub const PUBLIC_KEY_SIZE: usize = kyber512::public_key_bytes();

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct KyberPublicKey {
    pk: kyber512::PublicKey,
}

impl Eq for KyberPublicKey {}

impl From<kyber512::PublicKey> for KyberPublicKey {
    #[inline]
    fn from(pk: kyber512::PublicKey) -> Self {
        Self { pk }
    }
}

impl Deref for KyberPublicKey {
    type Target = kyber512::PublicKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.pk
    }
}

impl AsRef<[u8]> for KyberPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.pk.as_bytes()
    }
}

impl TryFrom<&[u8]> for KyberPublicKey {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        kyber512::PublicKey::from_bytes(value)
            .map(Self::from)
            .map_err(|_| Error::Message("Dilithium key deserialization failed".to_owned()))
    }
}

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct KyberSecretKey {
    sk: kyber512::SecretKey,
}

impl fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberSK").field("sk", &"[..]").finish()
    }
}

impl Eq for KyberSecretKey {}

impl Zeroize for KyberSecretKey {
    fn zeroize(&mut self) {
        // FIXME
        // self.sk.zeroize()
    }
}

impl From<kyber512::SecretKey> for KyberSecretKey {
    #[inline]
    fn from(sk: kyber512::SecretKey) -> Self {
        Self { sk }
    }
}

impl Deref for KyberSecretKey {
    type Target = kyber512::SecretKey;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

impl AsRef<[u8]> for KyberSecretKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.sk.as_bytes()
    }
}

impl TryFrom<&[u8]> for KyberSecretKey {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        kyber512::SecretKey::from_bytes(value)
            .map(Self::from)
            .map_err(|_| Error::Message("Kyber key deserialization failed".to_owned()))
    }
}

/// Generate a Kyber KeyPair.
pub fn generate_key() -> (KyberPublicKey, KyberSecretKey) {
    let (pk, sk) = kyber512::keypair();
    (pk.into(), sk.into())
}

/// Kyber decryption.
pub fn decrypt(priv_key: &KyberSecretKey, mpis: &[Mpi], fingerprint: &[u8]) -> Result<Vec<u8>> {
    debug!("Kyber decrypt");

    ensure_eq!(mpis.len(), 3);

    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = mpis[2].as_bytes();

    let ciphertext = {
        let ciphertext = from_mpi(&mpis[0])?;
        kyber512::Ciphertext::from_bytes(ciphertext.as_slice())
            .map_err(|_| Error::Message("Invalid ciphertext".to_owned()))?
    };

    // derive shared secret
    let shared_secret = kyber512::decapsulate(&ciphertext, priv_key);

    // Perform key derivation
    let z = kdf(shared_secret.as_bytes(), fingerprint);

    // Peform AES Key Unwrap
    let encrypted_key_len: usize = mpis[1].first().copied().unwrap_or(0) as usize;

    let mut encrypted_session_key_vec = vec![0u8; encrypted_key_len];
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let mut decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;
    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    {
        let len = decrypted_key_padded.len();
        let block_size = 8;
        ensure!(len % block_size == 0, "invalid key length {}", len);
        ensure!(!decrypted_key_padded.is_empty(), "empty key is not valid");

        // grab the last block
        let offset = len - block_size;
        let last_block = GenericArray::<u8, U8>::from_slice(&decrypted_key_padded[offset..]);
        let unpadded_last_block = Pkcs7::unpad(last_block)?;
        let unpadded_len = offset + unpadded_last_block.len();
        decrypted_key_padded.truncate(unpadded_len);
    }

    Ok(decrypted_key_padded)
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// https://tools.ietf.org/html/rfc6637#section-7
fn kdf(shared_secret: &[u8], fingerprint: &[u8]) -> Vec<u8> {
    let mut hasher = sha3::Sha3_512::default();
    hasher.update([0, 0, 0, 1]);
    hasher.update(shared_secret);
    hasher.update([OID.len() as u8]);
    hasher.update(OID);
    hasher.update([
        PublicKeyAlgorithm::Kyber as u8,
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        HASH as u8,
        CIPHER as u8,
    ]);
    hasher.update(ANON_SENDER);
    hasher.update(fingerprint);

    hasher.finalize()[..CIPHER.key_size()].to_vec()
}

/// Kyber encryption.
pub fn encrypt(
    their_public: &KyberPublicKey,
    fingerprint: &[u8],
    plain: &[u8],
) -> Result<Vec<Vec<u8>>> {
    debug!("Kyber encrypt");

    // derive shared secret
    let (shared_secret, ciphertext) = kyber512::encapsulate(their_public);

    // Perform key derivation
    let z = kdf(shared_secret.as_bytes(), fingerprint);

    // PKCS5 padding (PKCS5 is PKCS7 with a blocksize of 8)
    let len = plain.len();
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(len + 8, 0);

    let plain_padded_ref = {
        let pos = len;
        let block_size = 8;
        let bs = block_size * (pos / block_size);
        ensure!(
            plain_padded.len() >= bs && plain_padded.len() - bs >= block_size,
            "unable to pad"
        );
        let buf = GenericArray::<u8, U8>::from_mut_slice(&mut plain_padded[bs..bs + block_size]);
        Pkcs7::pad(buf, pos - bs);
        &plain_padded[..bs + block_size]
    };

    // Peform AES Key Wrap
    let encrypted_key = aes_kw::wrap(&z, plain_padded_ref)?;
    let encrypted_key_len = vec![encrypted_key.len() as u8];

    Ok(vec![
        as_mpi(&ciphertext.as_bytes()).as_bytes().into(),
        encrypted_key_len,
        encrypted_key,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let (pkey, skey) = generate_key();
        let mut fingerprint = vec![0u8; 20];
        rng.fill_bytes(&mut fingerprint);

        let plain = b"hello world";

        let mpis = encrypt(&pkey, &fingerprint, &plain[..]).expect("Unable to encrypt");
        let mpis = mpis.into_iter().map(Into::into).collect::<Vec<Mpi>>();

        let decrypted = decrypt(&skey, &mpis, &fingerprint).expect("Unable to decrypt");

        assert_eq!(&plain[..], &decrypted[..]);
    }
}
