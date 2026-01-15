/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use crate::{ErrorCode, InternalError};
use std::{borrow::Cow, collections::BTreeSet, fmt::Debug, num::NonZeroU32};

const INVALID_ARGS: ErrorCode = ErrorCode::InternalError(InternalError::InvalidArguments);

// ==========================================================================
// Flags trait
// ==========================================================================

pub(crate) trait Flags: Copy + Clone + Sized + Ord {
    fn stringify(self) -> Cow<'static, str>;
    fn validate_set(list: &BTreeSet<Self>) -> bool;

    fn as_string(list: Option<&[Self]>) -> Result<Option<String>, ErrorCode> {
        match list {
            Some(flags) => {
                let unqiue = if !flags.is_empty() { BTreeSet::from_iter(flags.iter().copied()) } else { BTreeSet::new() };
                if unqiue.is_empty() || (!Self::validate_set(&unqiue)) {
                    Err(INVALID_ARGS)
                } else {
                    Ok(Some(unqiue.into_iter().map(Self::stringify).collect::<Vec<Cow<'static, str>>>().join(",")))
                }
            }
            None => Ok(None), /*No flags, but that's okay!*/
        }
    }
}

// ==========================================================================
// Key creation flags
// ==========================================================================

/// Key creation flags, as used by the [`create_key()`](crate::FapiContext::create_key) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum KeyFlags {
    /// The private portion of the key may be used to decrypt.
    Decrypt,
    /// The key may be exported from the TPM. By default, the key is **not** exportable.
    Exportable,
    /// The key is not subject to dictionary attack protections.
    NoDA,
    /// Key usage is restricted to manipulate structures of known format.
    Restricted,
    /// The private portion of the key may be used to sign.
    Sign,
    /// Store the key in the system-wide directory.
    System,
    /// Approval of USER role actions with this key may be with an HMAC session or with a password using the authValue of the object or a policy session.
    User,
    /// Store key persistent in NV RAM. Contains the persistent handle which should be used.
    Persistent(NonZeroU32),
}

impl Flags for KeyFlags {
    fn stringify(self) -> Cow<'static, str> {
        match self {
            Self::Decrypt => Cow::Borrowed("decrypt"),
            Self::Exportable => Cow::Borrowed("exportable"),
            Self::NoDA => Cow::Borrowed("noda"),
            Self::Restricted => Cow::Borrowed("restricted"),
            Self::Sign => Cow::Borrowed("sign"),
            Self::System => Cow::Borrowed("system"),
            Self::User => Cow::Borrowed("user"),
            Self::Persistent(handle) => Cow::Owned(format!("0x{:08X}", handle)),
        }
    }

    fn validate_set(_flags: &BTreeSet<Self>) -> bool {
        true
    }
}

// ==========================================================================
// NV index creation flags
// ==========================================================================

/// NV index creation flags, as used by the [`create_nv()`](crate::FapiContext::create_nv) function.
///
/// *Note:* The Flags [`BitField`](NvFlags::BitField), [`Counter`](NvFlags::Counter) and [`PCR`](NvFlags::PCR) are mutually exclusive! If **no** type flag is given, an "ordinary" NV index is created.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum NvFlags {
    /// NV index contains an 8-octet value to be used as a bit field and can only be modified with `TPM2_NV_SetBits`.
    BitField,
    /// NV index contains an 8-octet value that is to be used as a counter and can only be modified with `TPM2_NV_Increment`.
    Counter,
    /// NV index contains a digestsized value used like a PCR. The Index can only be modified using `TPM2_NV_Extend`.
    PCR,
    /// NV index is not subject to dictionary attack protections.
    NoDA,
    /// Store the NV index in the system-wide directory.
    System,
    /// Store the NV index using the contained persistent handle value.
    Index(NonZeroU32),
}

impl Flags for NvFlags {
    fn stringify(self) -> Cow<'static, str> {
        match self {
            Self::BitField => Cow::Borrowed("bitfield"),
            Self::Counter => Cow::Borrowed("counter"),
            Self::NoDA => Cow::Borrowed("noda"),
            Self::PCR => Cow::Borrowed("pcr"),
            Self::System => Cow::Borrowed("system"),
            Self::Index(handle) => Cow::Owned(format!("0x{:08X}", handle)),
        }
    }

    fn validate_set(flags: &BTreeSet<Self>) -> bool {
        flags.iter().copied().filter(|flag| matches!(*flag, Self::BitField | Self::Counter | Self::PCR)).count() < 2usize
    }
}

// ==========================================================================
// Seal creation flags
// ==========================================================================

/// Sealed object creation flags, as used by the [`create_seal()`](crate::FapiContext::create_seal) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum SealFlags {
    /// Sealed object is not subject to dictionary attack protections.
    NoDA,
    /// Store the sealed object in the system-wide directory.
    System,
    /// Store the sealed object using the contained persistent handle value.
    Index(NonZeroU32),
}

impl Flags for SealFlags {
    fn stringify(self) -> Cow<'static, str> {
        match self {
            Self::NoDA => Cow::Borrowed("noda"),
            Self::System => Cow::Borrowed("system"),
            Self::Index(handle) => Cow::Owned(format!("0x{:08X}", handle)),
        }
    }

    fn validate_set(_flags: &BTreeSet<Self>) -> bool {
        true
    }
}

// ==========================================================================
// Quote creation flags
// ==========================================================================

/// Quote creation flags, as used by the [`quote()`](crate::FapiContext::quote) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum QuoteFlags {
    /// This is currently the only allowed type of attestation.
    TpmQuote,
}

impl Flags for QuoteFlags {
    fn stringify(self) -> Cow<'static, str> {
        match self {
            Self::TpmQuote => Cow::Borrowed("TPM-Quote"),
        }
    }

    fn validate_set(_list: &BTreeSet<Self>) -> bool {
        true
    }
}

// ==========================================================================
// Padding algorithm
// ==========================================================================

/// Padding algorithm to be used with [`sign()`](crate::FapiContext::sign) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum PaddingFlags {
    /// RSASSA PKCS1-v1.5 signature scheme
    RsaSsa,
    /// RSASSA-PSS PKCS#1-v2.1 probabilistic signature scheme
    RsaPss,
}

impl Flags for PaddingFlags {
    fn stringify(self) -> Cow<'static, str> {
        match self {
            Self::RsaSsa => Cow::Borrowed("RSA_SSA"),
            Self::RsaPss => Cow::Borrowed("RSA_PSS"),
        }
    }

    fn validate_set(flags: &BTreeSet<Self>) -> bool {
        flags.len() < 2usize
    }
}

// ==========================================================================
// ESYS blob types
// ==========================================================================

/// Blob type to be used with [`get_esys_blob()`](crate::FapiContext::get_esys_blob) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[non_exhaustive]
pub enum BlobType {
    ContextLoad,
    Deserialize,
}

impl TryFrom<u8> for BlobType {
    type Error = ErrorCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1u8 => Ok(BlobType::ContextLoad),
            2u8 => Ok(BlobType::Deserialize),
            _ => Err(INVALID_ARGS),
        }
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{BlobType, Flags, KeyFlags, NvFlags, PaddingFlags, QuoteFlags, SealFlags};
    use std::num::NonZeroU32;

    #[test]
    fn test_flags_to_string() {
        let index = NonZeroU32::new(1u32).unwrap();

        assert!(Flags::as_string(None::<&[KeyFlags]>).is_ok());
        assert!(
            Flags::as_string(Some(&[
                KeyFlags::Decrypt,
                KeyFlags::Exportable,
                KeyFlags::NoDA,
                KeyFlags::Persistent(index),
                KeyFlags::Restricted,
                KeyFlags::Sign,
                KeyFlags::System,
                KeyFlags::User
            ]))
            .is_ok()
        );

        assert!(Flags::as_string(None::<&[NvFlags]>).is_ok());
        assert!(Flags::as_string(Some(&[NvFlags::BitField, NvFlags::Index(index), NvFlags::NoDA, NvFlags::System])).is_ok());
        assert!(Flags::as_string(Some(&[NvFlags::PCR, NvFlags::Index(index), NvFlags::NoDA, NvFlags::System])).is_ok());
        assert!(Flags::as_string(Some(&[NvFlags::Counter, NvFlags::Index(index), NvFlags::NoDA, NvFlags::System])).is_ok());
        assert!(Flags::as_string(Some(&[NvFlags::BitField, NvFlags::Counter])).is_err());
        assert!(Flags::as_string(Some(&[NvFlags::BitField, NvFlags::PCR])).is_err());
        assert!(Flags::as_string(Some(&[NvFlags::Counter, NvFlags::PCR])).is_err());

        assert!(Flags::as_string(None::<&[SealFlags]>).is_ok());
        assert!(Flags::as_string(Some(&[SealFlags::NoDA, SealFlags::Index(index), SealFlags::System])).is_ok());

        assert!(Flags::as_string(None::<&[QuoteFlags]>).is_ok());
        assert!(Flags::as_string(Some(&[QuoteFlags::TpmQuote])).is_ok());

        assert!(Flags::as_string(None::<&[PaddingFlags]>).is_ok());
        assert!(Flags::as_string(Some(&[PaddingFlags::RsaPss])).is_ok());
        assert!(Flags::as_string(Some(&[PaddingFlags::RsaSsa])).is_ok());
        assert!(Flags::as_string(Some(&[PaddingFlags::RsaPss, PaddingFlags::RsaSsa])).is_err());
    }

    #[test]
    fn test_blob_types() {
        assert!(BlobType::try_from(1u8).is_ok());
        assert!(BlobType::try_from(2u8).is_ok());
        assert!(BlobType::try_from(3u8).is_err());
    }
}
