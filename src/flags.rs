/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use crate::{ErrorCode, InternalError};
use std::{borrow::Cow, collections::BTreeSet, fmt::Debug, num::NonZeroU32};

// ==========================================================================
// Flags trait
// ==========================================================================

pub(crate) trait Flags<T: Ord> {
    fn as_string(&self) -> Cow<'static, str>;
    fn ordinal(&self) -> usize;
    fn validate(list: &[T]) -> bool;
}

// ==========================================================================
// Key creation flags
// ==========================================================================

/// Key creation flags, as used by the [`create_key()`](crate::FapiContext::create_key) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
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

impl Flags<Self> for KeyFlags {
    fn as_string(&self) -> Cow<'static, str> {
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

    fn ordinal(&self) -> usize {
        match self {
            Self::Decrypt => 0x01usize,
            Self::Exportable => 0x02usize,
            Self::NoDA => 0x04usize,
            Self::Restricted => 0x08usize,
            Self::Sign => 0x10usize,
            Self::System => 0x20usize,
            Self::User => 0x40usize,
            Self::Persistent(_) => 0x80usize,
        }
    }

    fn validate(_list: &[Self]) -> bool {
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

impl Flags<Self> for NvFlags {
    fn as_string(&self) -> Cow<'static, str> {
        match self {
            Self::BitField => Cow::Borrowed("bitfield"),
            Self::Counter => Cow::Borrowed("counter"),
            Self::NoDA => Cow::Borrowed("noda"),
            Self::PCR => Cow::Borrowed("pcr"),
            Self::System => Cow::Borrowed("system"),
            Self::Index(handle) => Cow::Owned(format!("0x{:08X}", handle)),
        }
    }

    fn ordinal(&self) -> usize {
        match self {
            Self::BitField => 0x01usize,
            Self::Counter => 0x02usize,
            Self::NoDA => 0x04usize,
            Self::PCR => 0x08usize,
            Self::System => 0x10usize,
            Self::Index(_) => 0x20usize,
        }
    }

    fn validate(list: &[Self]) -> bool {
        list.iter().map(|flag| matches!(flag, Self::BitField | Self::Counter | Self::PCR)).map(usize::from).sum::<usize>() < 2usize
    }
}

// ==========================================================================
// Seal creation flags
// ==========================================================================

/// Sealed object creation flags, as used by the [`create_seal()`](crate::FapiContext::create_seal) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum SealFlags {
    /// Sealed object is not subject to dictionary attack protections.
    NoDA,
    /// Store the sealed object in the system-wide directory.
    System,
    /// Store the sealed object using the contained persistent handle value.
    Index(NonZeroU32),
}

impl Flags<Self> for SealFlags {
    fn as_string(&self) -> Cow<'static, str> {
        match self {
            Self::NoDA => Cow::Borrowed("noda"),
            Self::System => Cow::Borrowed("system"),
            Self::Index(handle) => Cow::Owned(format!("0x{:08X}", handle)),
        }
    }

    fn ordinal(&self) -> usize {
        match self {
            Self::NoDA => 0x01usize,
            Self::System => 0x02usize,
            Self::Index(_) => 0x04usize,
        }
    }

    fn validate(_list: &[Self]) -> bool {
        true
    }
}

// ==========================================================================
// Quote creation flags
// ==========================================================================

/// Quote creation flags, as used by the [`quote()`](crate::FapiContext::quote) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum QuoteFlags {
    /// This is currently the only allowed type of attestation.
    TpmQuote,
}

impl Flags<Self> for QuoteFlags {
    fn as_string(&self) -> Cow<'static, str> {
        match self {
            Self::TpmQuote => Cow::Borrowed("TPM-Quote"),
        }
    }

    fn ordinal(&self) -> usize {
        match self {
            Self::TpmQuote => 0x01usize,
        }
    }

    fn validate(_list: &[Self]) -> bool {
        true
    }
}

// ==========================================================================
// Padding algorithm
// ==========================================================================

/// Padding algorithm to be used with [`sign()`](crate::FapiContext::sign) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum PaddingFlags {
    /// RSASSA PKCS1-v1.5 signature scheme
    RsaSsa,
    /// RSASSA-PSS PKCS#1-v2.1 probabilistic signature scheme
    RsaPss,
}

impl Flags<Self> for PaddingFlags {
    fn as_string(&self) -> Cow<'static, str> {
        match self {
            Self::RsaSsa => Cow::Borrowed("RSA_SSA"),
            Self::RsaPss => Cow::Borrowed("RSA_PSS"),
        }
    }

    fn ordinal(&self) -> usize {
        match self {
            Self::RsaSsa => 0x01usize,
            Self::RsaPss => 0x02usize,
        }
    }

    fn validate(list: &[Self]) -> bool {
        list.len() < 2usize
    }
}

// ==========================================================================
// ESYS blob types
// ==========================================================================

/// Blob type to be used with [`get_esys_blob()`](crate::FapiContext::get_esys_blob) function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum BlobType {
    ContextLoad,
    Deserialize,
}

#[derive(Clone, Copy, Debug)]
pub struct UnknownFlagError;

impl TryFrom<u8> for BlobType {
    type Error = UnknownFlagError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1u8 => Ok(BlobType::ContextLoad),
            2u8 => Ok(BlobType::Deserialize),
            _ => Err(UnknownFlagError),
        }
    }
}

// ==========================================================================
// Helper functions
// ==========================================================================

pub(crate) fn flags_to_string<T: Flags<T> + Ord + Debug + Copy>(list: Option<&[T]>) -> Result<Option<String>, ErrorCode> {
    match list {
        Some(flags) => {
            if flags.is_empty() || contains_duplicates(flags) || (!T::validate(flags)) {
                Err(crate::ErrorCode::InternalError(InternalError::InvalidArguments))
            } else {
                Ok(Some(BTreeSet::from_iter(flags).into_iter().map(T::as_string).collect::<Vec<Cow<'static, str>>>().join(",")))
            }
        }
        None => Ok(None), /*No flags, but that's okay!*/
    }
}

fn contains_duplicates<T: Flags<T> + Ord + Copy>(list: &[T]) -> bool {
    for i in 0..list.len() {
        for j in i + 1..list.len() {
            if list[i].ordinal() == list[j].ordinal() {
                return true;
            }
        }
    }
    false /* no duplicates found! */
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{BlobType, KeyFlags, NvFlags, PaddingFlags, QuoteFlags, SealFlags, flags_to_string};
    use std::num::NonZeroU32;

    #[test]
    fn test_flags_to_string() {
        let index = NonZeroU32::new(1u32).unwrap();

        assert!(flags_to_string::<KeyFlags>(None).is_ok());
        assert!(flags_to_string::<NvFlags>(None).is_ok());
        assert!(flags_to_string::<SealFlags>(None).is_ok());
        assert!(flags_to_string::<QuoteFlags>(None).is_ok());
        assert!(flags_to_string::<PaddingFlags>(None).is_ok());

        assert!(
            flags_to_string(Some(&[
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

        assert!(flags_to_string(Some(&[KeyFlags::Decrypt, KeyFlags::Decrypt])).is_err());

        assert!(flags_to_string(Some(&[NvFlags::BitField, NvFlags::Index(index), NvFlags::NoDA, NvFlags::System])).is_ok());

        assert!(flags_to_string(Some(&[NvFlags::BitField, NvFlags::Counter])).is_err());
        assert!(flags_to_string(Some(&[NvFlags::BitField, NvFlags::PCR])).is_err());
        assert!(flags_to_string(Some(&[NvFlags::Counter, NvFlags::PCR])).is_err());
        assert!(flags_to_string(Some(&[NvFlags::BitField, NvFlags::BitField])).is_err());

        assert!(flags_to_string(Some(&[SealFlags::NoDA, SealFlags::Index(index), SealFlags::System])).is_ok());

        assert!(flags_to_string(Some(&[SealFlags::NoDA, SealFlags::NoDA])).is_err());

        assert!(flags_to_string(Some(&[QuoteFlags::TpmQuote])).is_ok());
        assert!(flags_to_string(Some(&[QuoteFlags::TpmQuote, QuoteFlags::TpmQuote])).is_err());

        assert!(flags_to_string(Some(&[PaddingFlags::RsaPss])).is_ok());
        assert!(flags_to_string(Some(&[PaddingFlags::RsaSsa])).is_ok());
        assert!(flags_to_string(Some(&[PaddingFlags::RsaPss, PaddingFlags::RsaPss])).is_err());
        assert!(flags_to_string(Some(&[PaddingFlags::RsaPss, PaddingFlags::RsaSsa])).is_err());
    }

    #[test]
    fn test_blob_types() {
        assert!(BlobType::try_from(1u8).is_ok());
        assert!(BlobType::try_from(2u8).is_ok());
        assert!(BlobType::try_from(3u8).is_err());
    }
}
