/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use p256::{
    PublicKey as EccPublicKey, SecretKey as EccPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use tss2_fapi_rs::HashAlgorithm;

// ==========================================================================
// Key types
// ==========================================================================

/// Identifies the type of the private key
#[derive(Debug)]
pub enum KeyType {
    RsaKey,
    EccKey,
}

macro_rules! key_type {
    ($name:ident, $id:literal, $type:path) => {
        if $name.get(..$id.len()).map_or(false, |id| id.eq_ignore_ascii_case($id)) {
            return Some($type);
        }
    };
}

/// Get key type from profile name
pub fn get_key_type(profile_name: &str) -> Option<KeyType> {
    key_type!(profile_name, "RSA", KeyType::RsaKey);
    key_type!(profile_name, "ECC", KeyType::EccKey);
    None
}

// ==========================================================================
// Key import functions
// ==========================================================================

/// Wrapper for the public key data
#[derive(Debug)]
pub enum PublicKey {
    RsaKey(RsaPublicKey),
    EccKey(EccPublicKey),
}

/// Wrapper for the private key data
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    RsaKey(RsaPrivateKey),
    EccKey(EccPrivateKey),
}

/// Load public key from PEM-encoded data
pub fn load_public_key(pem_data: &str, key_type: KeyType) -> Option<PublicKey> {
    match key_type {
        KeyType::RsaKey => RsaPublicKey::from_public_key_pem(pem_data).map(PublicKey::RsaKey).ok(),
        KeyType::EccKey => EccPublicKey::from_public_key_pem(pem_data).map(PublicKey::EccKey).ok(),
    }
}

/// Load private key from PEM-encoded data
pub fn load_private_key(pem_data: &str, key_type: KeyType) -> Option<PrivateKey> {
    match key_type {
        KeyType::RsaKey => RsaPrivateKey::from_pkcs8_pem(pem_data).map(PrivateKey::RsaKey).ok(),
        KeyType::EccKey => EccPrivateKey::from_pkcs8_pem(pem_data).map(PrivateKey::EccKey).ok(),
    }
}

// ==========================================================================
// Signature computation
// ==========================================================================

/// Compute signature using the given private key
pub fn create_signature(private_key: &PrivateKey, hash_algo: &HashAlgorithm, message: &[u8]) -> Option<Vec<u8>> {
    match private_key {
        PrivateKey::RsaKey(rsa_key) => sig_rsa::create_signature(rsa_key, hash_algo, message),
        PrivateKey::EccKey(ecc_key) => sig_ecc::create_signature(ecc_key, hash_algo, message),
    }
}

/// Compute signature using the RSA-SSA scheme
mod sig_rsa {
    use digest::{Digest, FixedOutputReset, Update};
    use rand::rng;
    use rsa::{
        RsaPrivateKey,
        pss::{Signature as RsaSignature, SigningKey as RsaSigningKey},
        signature::{RandomizedDigestSigner as RsaRandomizedDigestSigner, SignatureEncoding},
    };
    use sha2::{Sha256, Sha384, Sha512};
    use tss2_fapi_rs::HashAlgorithm;

    pub fn create_signature(private_key: &RsaPrivateKey, hash_algo: &HashAlgorithm, message: &[u8]) -> Option<Vec<u8>> {
        match hash_algo {
            HashAlgorithm::Sha2_256 => Some(do_create_signature::<Sha256>(private_key, message)),
            HashAlgorithm::Sha2_384 => Some(do_create_signature::<Sha384>(private_key, message)),
            HashAlgorithm::Sha2_512 => Some(do_create_signature::<Sha512>(private_key, message)),
            _ => None,
        }
    }

    fn do_create_signature<D: Digest + FixedOutputReset>(private_key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
        let sign_key = RsaSigningKey::<D>::from(private_key.to_owned());
        RsaRandomizedDigestSigner::<D, RsaSignature>::sign_digest_with_rng(&sign_key, &mut rng(), |dig| Update::update(dig, message)).to_vec()
    }
}

/// Compute signature using the ECDSA-scheme on NIST P-256 curve
mod sig_ecc {
    use digest::Update;
    use p256::{
        SecretKey as EccPrivateKey,
        ecdsa::{Signature as EccSignature, SigningKey as EccSigningKey, signature::RandomizedDigestSigner as EccRandomizedDigestSigner},
    };
    use rand::rng;
    use sha2::Sha256;
    use tss2_fapi_rs::HashAlgorithm;

    pub fn create_signature(private_key: &EccPrivateKey, hash_algo: &HashAlgorithm, message: &[u8]) -> Option<Vec<u8>> {
        match hash_algo {
            HashAlgorithm::Sha2_256 => Some(do_create_signature(private_key, message)),
            _ => None,
        }
    }

    fn do_create_signature(private_key: &EccPrivateKey, message: &[u8]) -> Vec<u8> {
        let sign_key = EccSigningKey::from(private_key);
        EccRandomizedDigestSigner::<Sha256, EccSignature>::sign_digest_with_rng(&sign_key, &mut rng(), |dig| dig.update(message)).to_der().as_bytes().to_vec()
    }
}
