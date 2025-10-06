/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use crate::fapi_sys::{TPM2_ALG_ID, constants};

/// Identifies the hash algorithm to be used, e.g. for signature creation.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// Secure Hash Algorithm 1
    Sha1,
    /// Secure Hash Algorithm 2 with 256-Bit output (SHA-256)
    Sha2_256,
    /// Secure Hash Algorithm 2 with 384-Bit output (SHA-384)
    Sha2_384,
    /// Secure Hash Algorithm 2 with 512-Bit output (SHA-512)
    Sha2_512,
    /// Secure Hash Algorithm 3 with 256-Bit output (SHA3-256)
    Sha3_256,
    /// Secure Hash Algorithm 3 with 384-Bit output (SHA3-384)
    Sha3_384,
    /// Secure Hash Algorithm 3 with 512-Bit output (SHA3-512)
    Sha3_512,
    /// ShangMi 3 hash function with 256-Bit output
    SM3_256,
    /// Unknown hash algorithm
    UnknownAlgorithm,
}

impl HashAlgorithm {
    pub(crate) fn from_id(algo_id: TPM2_ALG_ID) -> Self {
        match algo_id {
            constants::TPM2_ALG_SHA1 => Self::Sha1,
            constants::TPM2_ALG_SHA256 => Self::Sha2_256,
            constants::TPM2_ALG_SHA384 => Self::Sha2_384,
            constants::TPM2_ALG_SHA512 => Self::Sha2_512,
            constants::TPM2_ALG_SHA3_256 => Self::Sha3_256,
            constants::TPM2_ALG_SHA3_384 => Self::Sha3_384,
            constants::TPM2_ALG_SHA3_512 => Self::Sha3_512,
            constants::TPM2_ALG_SM3_256 => Self::SM3_256,
            _ => Self::UnknownAlgorithm,
        }
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::HashAlgorithm;
    use std::collections::HashSet;

    #[test]
    fn test_hash_ids() {
        let mut id_set: HashSet<HashAlgorithm> = HashSet::new();
        for algorithm_id in 0u16..=0xFFFF_u16 {
            match HashAlgorithm::from_id(algorithm_id) {
                HashAlgorithm::UnknownAlgorithm => (),
                identifier => assert!(id_set.insert(identifier)),
            }
        }
        assert_eq!(id_set.len(), 8usize);
    }
}
