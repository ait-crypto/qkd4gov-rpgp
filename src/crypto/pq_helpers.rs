use crate::{
    errors::{Error, Result},
    types::Mpi,
};

/// This marker is used to prevent [Mpi] from stripping leading zero bits.
const MARKER: u8 = 0xff;
/// Maximum number of bytes to encode per [Mpi] value.
pub const MAX_SIZE: usize = crate::types::MAX_EXTERN_MPI_BITS as usize / 8 - 1;

/// Convert a byte-arrayish not exceeding the maximum size into [Mpi]s
pub fn as_mpi(value: &impl AsRef<[u8]>) -> Mpi {
    as_mpi_(value.as_ref())
}

fn as_mpi_(bytes: &[u8]) -> Mpi {
    assert!(bytes.len() <= MAX_SIZE);

    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.push(MARKER);
    v.extend_from_slice(bytes);
    Mpi::from_raw(v)
}

/// Convert a byte-arrayish into multiple [Mpi]s
pub fn as_mpis(value: &impl AsRef<[u8]>) -> Vec<Mpi> {
    let bytes = value.as_ref();
    bytes.chunks(MAX_SIZE).map(as_mpi_).collect()
}

/// Convert [Mpi]s back into a [u8] vector
pub fn from_mpis(mpis: &[Mpi]) -> Result<Vec<u8>> {
    let mut ret = Vec::new();
    for mpi in mpis {
        let bytes = mpi.as_bytes();
        if bytes.is_empty() {
            // empty Mpis are only supposed to be at the end
            break;
        }
        if bytes[0] != MARKER {
            return Err(Error::Message("Invalid Mpi packet".to_owned()));
        }

        ret.extend_from_slice(&bytes[1..]);
    }
    Ok(ret)
}

/// Convert a single [Mpi] back into a [u8] vector
pub fn from_mpi(mpi: &Mpi) -> Result<Vec<u8>> {
    let bytes = mpi.as_bytes();
    if !bytes.is_empty() {
        if bytes[0] != MARKER {
            Err(Error::Message("Invalid Mpi packet".to_owned()))
        } else {
            Ok((&bytes[1..]).into())
        }
    } else {
        Ok(Vec::new())
    }
}

pub fn strip_marker(bytes: &[u8]) -> Result<&[u8]> {
    if !bytes.is_empty() && bytes[0] == MARKER {
        Ok(&bytes[1..])
    } else {
        Err(Error::Message("Invalid Mpi packet".to_owned()))
    }
}

#[cfg(test)]
mod test {
    use super::{as_mpi, as_mpis, from_mpi, from_mpis, MAX_SIZE};

    #[test]
    fn single_mpi() {
        let orig = b"some bytes for no good reason";
        assert!(orig.len() < MAX_SIZE);

        let mpi = as_mpi(orig);
        let converted = from_mpi(&mpi).expect("Unable to convert from Mpi");
        assert_eq!(orig, converted.as_slice());
    }

    #[test]
    fn multiple_mpi() {
        let orig = [0u8; 2 * MAX_SIZE];
        assert!(orig.len() > MAX_SIZE);

        let mpis = as_mpis(&orig);
        assert!(mpis.len() > 1);
        let converted = from_mpis(&mpis).expect("Unable to convert from Mpis");
        assert_eq!(orig, converted.as_slice());
    }
}
