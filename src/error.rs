/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use crate::fapi_sys::{constants, TSS2_RC};

const LAYER_BIT_MASK: u32 = 0x0000FFFF;

/// The error type for FAPI operations, used by the [`FapiContext`](crate::FapiContext) struct.
#[derive(Debug, PartialEq)]
pub enum ErrorCode {
    TpmError(Tpm2ErrorCode),
    FapiError(BaseErrorCode),
    EsysApiError(BaseErrorCode),
    SysApiError(BaseErrorCode),
    MuApiError(BaseErrorCode),
    TctiError(BaseErrorCode),
    ResMgrError(BaseErrorCode),
    ResMgrTpmError(BaseErrorCode),
    OtherError(BaseErrorCode),
    InternalError(InternalError),
}

/// Generic TSS2 error codes.
#[derive(Debug, PartialEq)]
pub enum BaseErrorCode {
    GeneralFailure,
    NotImplemented,
    BadContext,
    AbiMismatch,
    BadReference,
    InsufficientBuffer,
    BadSequence,
    NoConnection,
    TryAgain,
    IoError,
    BadValue,
    NotPermitted,
    InvalidSessions,
    NoDecryptParam,
    NoEncryptParam,
    BadSize,
    MalformedResponse,
    InsufficientContext,
    InsufficientResponse,
    IncompatibleTcti,
    NotSupported,
    BadTctiStructure,
    Memory,
    BadTr,
    MultipleDecryptSessions,
    MultipleEncryptSessions,
    RspAuthFailed,
    NoConfig,
    BadPath,
    NotDeletable,
    PathAlreadyExists,
    KeyNotFound,
    SignatureVerificationFailed,
    HashMismatch,
    KeyNotDuplicable,
    PathNotFound,
    NoCert,
    NoPcr,
    PcrNotResettable,
    BadTemplate,
    AuthorizationFailed,
    AuthorizationUnknown,
    NvNotRadable,
    NvTooSmall,
    NvNotWriteable,
    PolicyUnknown,
    NvWrongType,
    NameAlreadyExists,
    NoTpm,
    BadKey,
    NoHandle,
    NotProvisioned,
    AlreadyProvisioned,
    CallbackNull,
    UnknownError(u32),
}

/// TPM 2.0 response code wrapper.
#[derive(Debug, PartialEq)]
pub enum Tpm2ErrorCode {
    Tpm2ErrFmt0(Tpm2ErrFmt0),
    Tpm2ErrFmt1(Tpm2ErrFmt1),
    Tpm2Warning(Tpm2Warning),
    Other(u32),
}

/// TPM 2.0 "format zero" response codes.
#[derive(Debug, PartialEq)]
pub enum Tpm2ErrFmt0 {
    Initialize,
    Failure,
    Sequence,
    Private,
    Hmac,
    Disabled,
    Exclusive,
    AuthType,
    AuthMissing,
    Policy,
    Pcr,
    PcrChanged,
    Upgrade,
    TooManyContexts,
    AuthUnavailable,
    Reboot,
    Unbalanced,
    CommandSize,
    CommandCode,
    AuthSize,
    AuthContext,
    NvRange,
    NvSize,
    NvLocked,
    NvAuthorization,
    NvUninitialized,
    NvSpace,
    NvDefined,
    BadContext,
    CpHash,
    Parent,
    NeedsTest,
    NoResult,
    Sensitive,
    Unknown(u32),
}

/// TPM 2.0 "format one" response codes.
#[derive(Debug, PartialEq)]
pub enum Tpm2ErrFmt1 {
    Asymmetric,
    Attributes,
    Hash,
    Value,
    Hierarchy,
    KeySize,
    Mgf,
    Mode,
    Type,
    Handle,
    Kdf,
    Range,
    AuthFail,
    Nonce,
    PP,
    Scheme,
    Size,
    Symmetric,
    Tag,
    Selector,
    Insufficient,
    Signature,
    Key,
    PolicyFail,
    Integrity,
    Ticket,
    ReservedBits,
    BadAuth,
    Expired,
    PolicyCC,
    Binding,
    Curve,
    EccPoint,
    Unknown(u32),
}

/// TPM 2.0 "warning" response codes.
#[derive(Debug, PartialEq)]
pub enum Tpm2Warning {
    ContextGap,
    ObjectMemory,
    SessionMemory,
    Memory,
    SessionHandles,
    ObjectHandles,
    Locality,
    Yielded,
    Cancelled,
    Testing,
    ReferenceH0,
    ReferenceH1,
    ReferenceH2,
    ReferenceH3,
    ReferenceH4,
    ReferenceH5,
    ReferenceH6,
    ReferenceS0,
    ReferenceS1,
    ReferenceS2,
    ReferenceS3,
    ReferenceS4,
    ReferenceS5,
    ReferenceS6,
    NvRate,
    Lockout,
    Retry,
    NvUnavailable,
    Other(u32),
}

/// Internal error codes.
#[derive(Debug, PartialEq)]
pub enum InternalError {
    NoResultData,
    InvalidArguments,
}

impl ErrorCode {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let layer_code = error_code & !LAYER_BIT_MASK;
        match layer_code {
            constants::TSS2_TPM_RC_LAYER => ErrorCode::TpmError(Tpm2ErrorCode::from_raw(error_code)),
            constants::TSS2_FEATURE_RC_LAYER => ErrorCode::FapiError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_ESAPI_RC_LAYER => ErrorCode::EsysApiError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_SYS_RC_LAYER => ErrorCode::SysApiError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_MU_RC_LAYER => ErrorCode::MuApiError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_TCTI_RC_LAYER => ErrorCode::TctiError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_RESMGR_RC_LAYER => ErrorCode::ResMgrError(BaseErrorCode::from_raw(error_code)),
            constants::TSS2_RESMGR_TPM_RC_LAYER => ErrorCode::ResMgrTpmError(BaseErrorCode::from_raw(error_code)),
            _ => ErrorCode::OtherError(BaseErrorCode::from_raw(error_code)),
        }
    }
}

impl BaseErrorCode {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let base_error = error_code & LAYER_BIT_MASK;
        match base_error {
            constants::TSS2_BASE_RC_GENERAL_FAILURE => BaseErrorCode::GeneralFailure,
            constants::TSS2_BASE_RC_NOT_IMPLEMENTED => BaseErrorCode::NotImplemented,
            constants::TSS2_BASE_RC_BAD_CONTEXT => BaseErrorCode::BadContext,
            constants::TSS2_BASE_RC_ABI_MISMATCH => BaseErrorCode::AbiMismatch,
            constants::TSS2_BASE_RC_BAD_REFERENCE => BaseErrorCode::BadReference,
            constants::TSS2_BASE_RC_INSUFFICIENT_BUFFER => BaseErrorCode::InsufficientBuffer,
            constants::TSS2_BASE_RC_BAD_SEQUENCE => BaseErrorCode::BadSequence,
            constants::TSS2_BASE_RC_NO_CONNECTION => BaseErrorCode::NoConnection,
            constants::TSS2_BASE_RC_TRY_AGAIN => BaseErrorCode::TryAgain,
            constants::TSS2_BASE_RC_IO_ERROR => BaseErrorCode::IoError,
            constants::TSS2_BASE_RC_BAD_VALUE => BaseErrorCode::BadValue,
            constants::TSS2_BASE_RC_NOT_PERMITTED => BaseErrorCode::NotPermitted,
            constants::TSS2_BASE_RC_INVALID_SESSIONS => BaseErrorCode::InvalidSessions,
            constants::TSS2_BASE_RC_NO_DECRYPT_PARAM => BaseErrorCode::NoDecryptParam,
            constants::TSS2_BASE_RC_NO_ENCRYPT_PARAM => BaseErrorCode::NoEncryptParam,
            constants::TSS2_BASE_RC_BAD_SIZE => BaseErrorCode::BadSize,
            constants::TSS2_BASE_RC_MALFORMED_RESPONSE => BaseErrorCode::MalformedResponse,
            constants::TSS2_BASE_RC_INSUFFICIENT_CONTEXT => BaseErrorCode::InsufficientContext,
            constants::TSS2_BASE_RC_INSUFFICIENT_RESPONSE => BaseErrorCode::InsufficientResponse,
            constants::TSS2_BASE_RC_INCOMPATIBLE_TCTI => BaseErrorCode::IncompatibleTcti,
            constants::TSS2_BASE_RC_NOT_SUPPORTED => BaseErrorCode::NotSupported,
            constants::TSS2_BASE_RC_BAD_TCTI_STRUCTURE => BaseErrorCode::BadTctiStructure,
            constants::TSS2_BASE_RC_MEMORY => BaseErrorCode::Memory,
            constants::TSS2_BASE_RC_BAD_TR => BaseErrorCode::BadTr,
            constants::TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS => BaseErrorCode::MultipleDecryptSessions,
            constants::TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS => BaseErrorCode::MultipleEncryptSessions,
            constants::TSS2_BASE_RC_RSP_AUTH_FAILED => BaseErrorCode::RspAuthFailed,
            constants::TSS2_BASE_RC_NO_CONFIG => BaseErrorCode::NoConfig,
            constants::TSS2_BASE_RC_BAD_PATH => BaseErrorCode::BadPath,
            constants::TSS2_BASE_RC_NOT_DELETABLE => BaseErrorCode::NotDeletable,
            constants::TSS2_BASE_RC_PATH_ALREADY_EXISTS => BaseErrorCode::PathAlreadyExists,
            constants::TSS2_BASE_RC_KEY_NOT_FOUND => BaseErrorCode::KeyNotFound,
            constants::TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED => BaseErrorCode::SignatureVerificationFailed,
            constants::TSS2_BASE_RC_HASH_MISMATCH => BaseErrorCode::HashMismatch,
            constants::TSS2_BASE_RC_KEY_NOT_DUPLICABLE => BaseErrorCode::KeyNotDuplicable,
            constants::TSS2_BASE_RC_PATH_NOT_FOUND => BaseErrorCode::PathNotFound,
            constants::TSS2_BASE_RC_NO_CERT => BaseErrorCode::NoCert,
            constants::TSS2_BASE_RC_NO_PCR => BaseErrorCode::NoPcr,
            constants::TSS2_BASE_RC_PCR_NOT_RESETTABLE => BaseErrorCode::PcrNotResettable,
            constants::TSS2_BASE_RC_BAD_TEMPLATE => BaseErrorCode::BadTemplate,
            constants::TSS2_BASE_RC_AUTHORIZATION_FAILED => BaseErrorCode::AuthorizationFailed,
            constants::TSS2_BASE_RC_AUTHORIZATION_UNKNOWN => BaseErrorCode::AuthorizationUnknown,
            constants::TSS2_BASE_RC_NV_NOT_READABLE => BaseErrorCode::NvNotRadable,
            constants::TSS2_BASE_RC_NV_TOO_SMALL => BaseErrorCode::NvTooSmall,
            constants::TSS2_BASE_RC_NV_NOT_WRITEABLE => BaseErrorCode::NvNotWriteable,
            constants::TSS2_BASE_RC_POLICY_UNKNOWN => BaseErrorCode::PolicyUnknown,
            constants::TSS2_BASE_RC_NV_WRONG_TYPE => BaseErrorCode::NvWrongType,
            constants::TSS2_BASE_RC_NAME_ALREADY_EXISTS => BaseErrorCode::NameAlreadyExists,
            constants::TSS2_BASE_RC_NO_TPM => BaseErrorCode::NoTpm,
            constants::TSS2_BASE_RC_BAD_KEY => BaseErrorCode::BadKey,
            constants::TSS2_BASE_RC_NO_HANDLE => BaseErrorCode::NoHandle,
            constants::TSS2_BASE_RC_NOT_PROVISIONED => BaseErrorCode::NotProvisioned,
            constants::TSS2_BASE_RC_ALREADY_PROVISIONED => BaseErrorCode::AlreadyProvisioned,
            constants::TSS2_BASE_RC_CALLBACK_NULL => BaseErrorCode::CallbackNull,
            _ => BaseErrorCode::UnknownError(base_error),
        }
    }
}

impl Tpm2ErrorCode {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let tpm2_error = error_code & LAYER_BIT_MASK;
        if tpm2_error & 0x80 == 0x80 {
            Tpm2ErrorCode::Tpm2ErrFmt1(Tpm2ErrFmt1::from_raw(tpm2_error)) /* if bit #7 is set -> "Format-One" error */
        } else if tpm2_error & 0x900 == 0x900 {
            Tpm2ErrorCode::Tpm2Warning(Tpm2Warning::from_raw(tpm2_error)) /* ...otherwise, if bits #8 and #11 are set -> "Format-Zero" warning */
        } else if tpm2_error & 0x100 == 0x100 {
            Tpm2ErrorCode::Tpm2ErrFmt0(Tpm2ErrFmt0::from_raw(tpm2_error)) /* ...otherwise, if bit #8 is set -> "Format-Zero" error */
        } else {
            Tpm2ErrorCode::Other(tpm2_error)
        }
    }
}

impl Tpm2ErrFmt0 {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let tpm2_error = error_code & 0x7F;
        match tpm2_error {
            constants::TPM_RC_INITIALIZE => Tpm2ErrFmt0::Initialize,
            constants::TPM_RC_FAILURE => Tpm2ErrFmt0::Failure,
            constants::TPM_RC_SEQUENCE => Tpm2ErrFmt0::Sequence,
            constants::TPM_RC_PRIVATE => Tpm2ErrFmt0::Private,
            constants::TPM_RC_HMAC => Tpm2ErrFmt0::Hmac,
            constants::TPM_RC_DISABLED => Tpm2ErrFmt0::Disabled,
            constants::TPM_RC_EXCLUSIVE => Tpm2ErrFmt0::Exclusive,
            constants::TPM_RC_AUTH_TYPE => Tpm2ErrFmt0::AuthType,
            constants::TPM_RC_AUTH_MISSING => Tpm2ErrFmt0::AuthMissing,
            constants::TPM_RC_POLICY => Tpm2ErrFmt0::Policy,
            constants::TPM_RC_PCR => Tpm2ErrFmt0::Pcr,
            constants::TPM_RC_PCR_CHANGED => Tpm2ErrFmt0::PcrChanged,
            constants::TPM_RC_UPGRADE => Tpm2ErrFmt0::Upgrade,
            constants::TPM_RC_TOO_MANY_CONTEXTS => Tpm2ErrFmt0::TooManyContexts,
            constants::TPM_RC_AUTH_UNAVAILABLE => Tpm2ErrFmt0::AuthUnavailable,
            constants::TPM_RC_REBOOT => Tpm2ErrFmt0::Reboot,
            constants::TPM_RC_UNBALANCED => Tpm2ErrFmt0::Unbalanced,
            constants::TPM_RC_COMMAND_SIZE => Tpm2ErrFmt0::CommandSize,
            constants::TPM_RC_COMMAND_CODE => Tpm2ErrFmt0::CommandCode,
            constants::TPM_RC_AUTHSIZE => Tpm2ErrFmt0::AuthSize,
            constants::TPM_RC_AUTH_CONTEXT => Tpm2ErrFmt0::AuthContext,
            constants::TPM_RC_NV_RANGE => Tpm2ErrFmt0::NvRange,
            constants::TPM_RC_NV_SIZE => Tpm2ErrFmt0::NvSize,
            constants::TPM_RC_NV_LOCKED => Tpm2ErrFmt0::NvLocked,
            constants::TPM_RC_NV_AUTHORIZATION => Tpm2ErrFmt0::NvAuthorization,
            constants::TPM_RC_NV_UNINITIALIZED => Tpm2ErrFmt0::NvUninitialized,
            constants::TPM_RC_NV_SPACE => Tpm2ErrFmt0::NvSpace,
            constants::TPM_RC_NV_DEFINED => Tpm2ErrFmt0::NvDefined,
            constants::TPM_RC_BAD_CONTEXT => Tpm2ErrFmt0::BadContext,
            constants::TPM_RC_CPHASH => Tpm2ErrFmt0::CpHash,
            constants::TPM_RC_PARENT => Tpm2ErrFmt0::Parent,
            constants::TPM_RC_NEEDS_TEST => Tpm2ErrFmt0::NeedsTest,
            constants::TPM_RC_NO_RESULT => Tpm2ErrFmt0::NoResult,
            constants::TPM_RC_SENSITIVE => Tpm2ErrFmt0::Sensitive,
            _ => Tpm2ErrFmt0::Unknown(tpm2_error),
        }
    }
}

impl Tpm2ErrFmt1 {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let tpm2_error = error_code & 0x3F;
        match tpm2_error {
            constants::TPM_RC_ASYMMETRIC => Tpm2ErrFmt1::Asymmetric,
            constants::TPM_RC_ATTRIBUTES => Tpm2ErrFmt1::Attributes,
            constants::TPM_RC_HASH => Tpm2ErrFmt1::Hash,
            constants::TPM_RC_VALUE => Tpm2ErrFmt1::Value,
            constants::TPM_RC_HIERARCHY => Tpm2ErrFmt1::Hierarchy,
            constants::TPM_RC_KEY_SIZE => Tpm2ErrFmt1::KeySize,
            constants::TPM_RC_MGF => Tpm2ErrFmt1::Mgf,
            constants::TPM_RC_MODE => Tpm2ErrFmt1::Mode,
            constants::TPM_RC_TYPE => Tpm2ErrFmt1::Type,
            constants::TPM_RC_HANDLE => Tpm2ErrFmt1::Handle,
            constants::TPM_RC_KDF => Tpm2ErrFmt1::Kdf,
            constants::TPM_RC_RANGE => Tpm2ErrFmt1::Range,
            constants::TPM_RC_AUTH_FAIL => Tpm2ErrFmt1::AuthFail,
            constants::TPM_RC_NONCE => Tpm2ErrFmt1::Nonce,
            constants::TPM_RC_PP => Tpm2ErrFmt1::PP,
            constants::TPM_RC_SCHEME => Tpm2ErrFmt1::Scheme,
            constants::TPM_RC_SIZE => Tpm2ErrFmt1::Size,
            constants::TPM_RC_SYMMETRIC => Tpm2ErrFmt1::Symmetric,
            constants::TPM_RC_TAG => Tpm2ErrFmt1::Tag,
            constants::TPM_RC_SELECTOR => Tpm2ErrFmt1::Selector,
            constants::TPM_RC_INSUFFICIENT => Tpm2ErrFmt1::Insufficient,
            constants::TPM_RC_SIGNATURE => Tpm2ErrFmt1::Signature,
            constants::TPM_RC_KEY => Tpm2ErrFmt1::Key,
            constants::TPM_RC_POLICY_FAIL => Tpm2ErrFmt1::PolicyFail,
            constants::TPM_RC_INTEGRITY => Tpm2ErrFmt1::Integrity,
            constants::TPM_RC_TICKET => Tpm2ErrFmt1::Ticket,
            constants::TPM_RC_RESERVED_BITS => Tpm2ErrFmt1::ReservedBits,
            constants::TPM_RC_BAD_AUTH => Tpm2ErrFmt1::BadAuth,
            constants::TPM_RC_EXPIRED => Tpm2ErrFmt1::Expired,
            constants::TPM_RC_POLICY_CC => Tpm2ErrFmt1::PolicyCC,
            constants::TPM_RC_BINDING => Tpm2ErrFmt1::Binding,
            constants::TPM_RC_CURVE => Tpm2ErrFmt1::Curve,
            constants::TPM_RC_ECC_POINT => Tpm2ErrFmt1::EccPoint,
            _ => Tpm2ErrFmt1::Unknown(tpm2_error),
        }
    }
}

impl Tpm2Warning {
    pub(crate) fn from_raw(error_code: TSS2_RC) -> Self {
        let tpm2_error = error_code & 0x7F;
        match tpm2_error {
            constants::TPM_RC_CONTEXT_GAP => Tpm2Warning::ContextGap,
            constants::TPM_RC_OBJECT_MEMORY => Tpm2Warning::ObjectMemory,
            constants::TPM_RC_SESSION_MEMORY => Tpm2Warning::SessionMemory,
            constants::TPM_RC_MEMORY => Tpm2Warning::Memory,
            constants::TPM_RC_SESSION_HANDLES => Tpm2Warning::SessionHandles,
            constants::TPM_RC_OBJECT_HANDLES => Tpm2Warning::ObjectHandles,
            constants::TPM_RC_LOCALITY => Tpm2Warning::Locality,
            constants::TPM_RC_YIELDED => Tpm2Warning::Yielded,
            constants::TPM_RC_CANCELED => Tpm2Warning::Cancelled,
            constants::TPM_RC_TESTING => Tpm2Warning::Testing,
            constants::TPM_RC_REFERENCE_H0 => Tpm2Warning::ReferenceH0,
            constants::TPM_RC_REFERENCE_H1 => Tpm2Warning::ReferenceH1,
            constants::TPM_RC_REFERENCE_H2 => Tpm2Warning::ReferenceH2,
            constants::TPM_RC_REFERENCE_H3 => Tpm2Warning::ReferenceH3,
            constants::TPM_RC_REFERENCE_H4 => Tpm2Warning::ReferenceH4,
            constants::TPM_RC_REFERENCE_H5 => Tpm2Warning::ReferenceH5,
            constants::TPM_RC_REFERENCE_H6 => Tpm2Warning::ReferenceH6,
            constants::TPM_RC_REFERENCE_S0 => Tpm2Warning::ReferenceS0,
            constants::TPM_RC_REFERENCE_S1 => Tpm2Warning::ReferenceS1,
            constants::TPM_RC_REFERENCE_S2 => Tpm2Warning::ReferenceS2,
            constants::TPM_RC_REFERENCE_S3 => Tpm2Warning::ReferenceS3,
            constants::TPM_RC_REFERENCE_S4 => Tpm2Warning::ReferenceS4,
            constants::TPM_RC_REFERENCE_S5 => Tpm2Warning::ReferenceS5,
            constants::TPM_RC_REFERENCE_S6 => Tpm2Warning::ReferenceS6,
            constants::TPM_RC_NV_RATE => Tpm2Warning::NvRate,
            constants::TPM_RC_LOCKOUT => Tpm2Warning::Lockout,
            constants::TPM_RC_RETRY => Tpm2Warning::Retry,
            constants::TPM_RC_NV_UNAVAILABLE => Tpm2Warning::NvUnavailable,
            _ => Tpm2Warning::Other(tpm2_error),
        }
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::ErrorCode;
    use std::collections::HashSet;

    #[test]
    fn test_error_codes() {
        let mut layer_set: HashSet<u8> = HashSet::new();
        for raw_value in 0u32..0x200000 {
            match ErrorCode::from_raw(raw_value) {
                ErrorCode::TpmError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0x0_u32);
                    layer_set.insert(1u8);
                }
                ErrorCode::FapiError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0x6_u32);
                    layer_set.insert(2u8);
                }
                ErrorCode::EsysApiError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0x7_u32);
                    layer_set.insert(3u8);
                }
                ErrorCode::SysApiError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0x8_u32);
                    layer_set.insert(4u8);
                }
                ErrorCode::MuApiError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0x9_u32);
                    layer_set.insert(5u8);
                }
                ErrorCode::TctiError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0xA_u32);
                    layer_set.insert(6u8);
                }
                ErrorCode::ResMgrError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0xB_u32);
                    layer_set.insert(7u8);
                }
                ErrorCode::ResMgrTpmError(_) => {
                    assert_eq!((raw_value >> 16) & 0xFF, 0xC_u32);
                    layer_set.insert(8u8);
                }
                ErrorCode::OtherError(_) => {
                    let high_word = (raw_value >> 16) & 0xFF;
                    assert!(((high_word > 0u32) && (high_word < 0x6_u32)) || (high_word > 0xC_u32));
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(layer_set.len(), 8usize);
    }
}
