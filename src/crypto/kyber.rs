use block_padding::{Padding, Pkcs7};

use crate::crypto::pq_helpers::{as_mpi, from_mpi, strip_marker};
use crate::crypto::{aes_kw, HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use crate::errors::{Error, Result};
use crate::types::{KyberSecretKey, Mpi, PlainSecretParams, PublicParams};

use pqcrypto_kyber::kyber512::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: &[u8; 20] = b"Anonymous Sender    ";

const OID: &[u8] = b"Kyber OID not yet specified";
const HASH: HashAlgorithm = HashAlgorithm::SHA3_512;
const CIPHER: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;

/// Generate a Kyber KeyPair.
pub fn generate_key() -> (PublicParams, PlainSecretParams) {
    let (pk, sk) = keypair();

    (
        PublicParams::Kyber {
            pk: as_mpi(&pk.as_bytes()),
        },
        PlainSecretParams::Kyber(as_mpi(&sk.as_bytes())),
    )
}

/// Kyber decryption.
pub fn decrypt(priv_key: &KyberSecretKey, mpis: &[Mpi], fingerprint: &[u8]) -> Result<Vec<u8>> {
    debug!("Kyber decrypt");

    ensure_eq!(mpis.len(), 3);

    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = mpis[2].as_bytes();

    let ciphertext = {
        let ciphertext = from_mpi(&mpis[0])?;
        Ciphertext::from_bytes(ciphertext.as_slice())
            .map_err(|_| Error::Message("Invalid ciphertext".to_owned()))?
    };

    let our_secret = SecretKey::from_bytes(strip_marker(&priv_key.secret)?)
        .map_err(|_| Error::Message("Invalid secret key".to_owned()))?;

    // derive shared secret
    let shared_secret = decapsulate(&ciphertext, &our_secret);

    // Perform key derivation
    let z = kdf(
        HASH,
        shared_secret.as_bytes(),
        CIPHER.key_size(),
        CIPHER,
        fingerprint,
    )?;

    // Peform AES Key Unwrap
    let encrypted_key_len: usize = match mpis[1].first() {
        Some(l) => *l as usize,
        None => 0,
    };

    let mut encrypted_session_key_vec: Vec<u8> = Vec::new();
    encrypted_session_key_vec.resize(encrypted_key_len, 0);
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;

    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    let decrypted_key = Pkcs7::unpad(&decrypted_key_padded)?;

    Ok(decrypted_key.to_vec())
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// https://tools.ietf.org/html/rfc6637#section-7
fn kdf(
    hash: HashAlgorithm,
    shared_secret: &[u8],
    length: usize,
    alg_sym: SymmetricKeyAlgorithm,
    fingerprint: &[u8],
) -> Result<Vec<u8>> {
    let mut hasher = hash.new_hasher()?;
    hasher.update(&[0, 0, 0, 1]);
    hasher.update(shared_secret);
    hasher.update(&[OID.len() as u8]);
    hasher.update(OID);
    hasher.update(&[PublicKeyAlgorithm::Kyber as u8]);
    hasher.update(&[
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ]);
    hasher.update(ANON_SENDER);
    hasher.update(fingerprint);

    let mut digest = hasher.finish();
    digest.truncate(length);

    Ok(digest)
}

/// Kyber encryption.
pub fn encrypt(pk: &Mpi, fingerprint: &[u8], plain: &[u8]) -> Result<Vec<Vec<u8>>> {
    debug!("Kyber encrypt");

    let their_public = {
        let pk = from_mpi(pk)?;
        PublicKey::from_bytes(&pk).map_err(|_| Error::Message("Invalid public key".to_owned()))?
    };

    // derive shared secret
    let (shared_secret, ciphertext) = encapsulate(&their_public);

    // Perform key derivation
    let z = kdf(
        HASH,
        shared_secret.as_bytes(),
        CIPHER.key_size(),
        CIPHER,
        fingerprint,
    )?;

    // PKCS5 padding (PKCS5 is PKCS7 with a blocksize of 8)
    let len = plain.len();
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(len + 8, 0);
    let plain_padded_ref = Pkcs7::pad(&mut plain_padded, len, 8)?;

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

    use crate::types::{PublicParams, SecretKeyRepr};

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let (pkey, skey) = generate_key();
        let mut fingerprint = vec![0u8; 20];
        rng.fill_bytes(&mut fingerprint);

        let plain = b"hello world";

        let mpis = match pkey {
            PublicParams::Kyber { ref pk } => {
                encrypt(pk, &fingerprint, &plain[..]).expect("Unable to encrypt")
            }
            _ => panic!("invalid key generated"),
        };

        let mpis = mpis.into_iter().map(Into::into).collect::<Vec<Mpi>>();

        let decrypted = match skey.as_ref().as_repr(&pkey).expect("Unable to decrypt") {
            SecretKeyRepr::Kyber(ref skey) => {
                decrypt(skey, &mpis, &fingerprint).expect("Unable to decrypt")
            }
            _ => panic!("invalid key generated"),
        };

        assert_eq!(&plain[..], &decrypted[..]);
    }
}
