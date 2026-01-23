/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use crate::{
    ErrorCode, InternalError,
    json::JsonValue,
    memory::{CBinaryHolder, CStringHolder},
};
use std::num::NonZeroUsize;

/* Const */
const ERR_INVALID_ARGUMENTS: ErrorCode = ErrorCode::InternalError(InternalError::InvalidArguments);

// ==========================================================================
// Helper macros
// ==========================================================================

macro_rules! not_empty {
    ($value:ident) => {
        (!$value.is_empty())
    };
}

macro_rules! opt_check {
    ($value:ident) => {
        $value.as_ref().is_none_or(|inner| not_empty!(inner))
    };
}

// ==========================================================================
// Import Data
// ==========================================================================

/// Data to be imported, either a [`&JsonValue`](json::JsonValue) or a PEM encoded [`&str`](core::primitive::str).
///
/// Instances of this struct may be used with the [`FapiContext::import()`](crate::FapiContext::import) function.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ImportData<'a> {
    #[non_exhaustive]
    Pem(&'a str),
    #[non_exhaustive]
    Json(&'a JsonValue),
}

impl<'a> ImportData<'a> {
    /// Attempts to create a new `ImportData` from the given `JsonValue` reference.
    ///
    /// This functions fails if the given JSON value is *empty*, but the JSON structure is **not** fully validated.
    ///
    /// The JSON data will be validated, by the FAPI, when it is actually used.
    pub fn from_json(json_value: &'a JsonValue) -> Result<Self, ErrorCode> {
        if json_value.is_object() && (!json_value.is_empty()) {
            Ok(Self::Json(json_value))
        } else {
            Err(ErrorCode::InternalError(InternalError::InvalidArguments))
        }
    }

    /// Attempts to create a new `ImportData` from the given PEM (Privacy-Enhanced Mail) encoded string.
    ///
    /// This functions fails if the given string does **not** look like a PEM encoded key, but the PEM key is **not** fully validated.
    ///
    /// The PEM data will be validated, by the FAPI, when it is actually used.
    pub fn from_pem(pem_data: &'a str) -> Result<Self, ErrorCode> {
        if pem_data.starts_with("-----BEGIN PUBLIC KEY-----")
            || pem_data.starts_with("-----BEGIN PRIVATE KEY-----")
            || pem_data.starts_with("-----BEGIN RSA PRIVATE KEY-----")
            || pem_data.starts_with("-----BEGIN EC PRIVATE KEY-----")
        {
            Ok(Self::Pem(pem_data))
        } else {
            Err(ERR_INVALID_ARGUMENTS)
        }
    }
}

impl TryFrom<ImportData<'_>> for CStringHolder {
    type Error = ErrorCode;

    fn try_from(data: ImportData) -> Result<Self, Self::Error> {
        match data {
            ImportData::Json(json_value) => CStringHolder::try_from(json_value),
            ImportData::Pem(pem_data) => CStringHolder::try_from(pem_data),
        }
    }
}

// ==========================================================================
// Seal Data
// ==========================================================================

/// The size of the sealed object and, optionally, the initial data.
pub type RawSealInfo = (NonZeroUsize, CBinaryHolder);

/// Data to be sealed, either a non-zero size or some explicit data.
///
/// Instances of this struct may be used with the [`FapiContext::create_seal()`](crate::FapiContext::create_seal) function.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum SealedData<'a> {
    #[non_exhaustive]
    Data(&'a [u8]),
    Size(NonZeroUsize),
}

impl<'a> SealedData<'a> {
    /// Creates a new `SealData` with the specified non-zero size.
    ///
    /// The new sealed object will be created with the specified size and will be initialized by the TPM with random data.
    pub fn from_size(size: usize) -> Result<Self, ErrorCode> {
        Ok(Self::Size(NonZeroUsize::new(size).ok_or(ERR_INVALID_ARGUMENTS)?))
    }

    /// Creates a new `SealData` containing the specified data.
    ///
    /// The new sealed object will be created with a size of `data.len()` and it will be initialized with the given data.
    pub fn from_data(data: &'a [u8]) -> Result<Self, ErrorCode> {
        if !data.is_empty() { Ok(Self::Data(data)) } else { Err(ERR_INVALID_ARGUMENTS) }
    }

    /// Returns the actual seal size and the associated data (if any)
    pub(crate) fn into_raw_data(self) -> Result<RawSealInfo, ErrorCode> {
        match self {
            Self::Size(size) => Ok((size, CBinaryHolder::empty())),
            Self::Data(data) => {
                let cstr_data = CBinaryHolder::try_from(data)?;
                let cstr_size = NonZeroUsize::new(cstr_data.len()).expect("Size must not be zero!");
                Ok((cstr_size, cstr_data))
            }
        }
    }
}

// ==========================================================================
// Sign Result
// ==========================================================================

/// Contains the result of a signing operation.
///
/// Instances of this struct are returned by the [`FapiContext::sign()`](crate::FapiContext::sign) function.
#[non_exhaustive]
pub struct SignResult {
    pub sign_value: Vec<u8>,
    pub public_key: Option<String>,
    pub certificate: Option<String>,
}

impl SignResult {
    pub fn from(sign_value: Vec<u8>, public_key: Option<String>, certificate: Option<String>) -> Self {
        assert!(not_empty!(sign_value) && opt_check!(public_key) && opt_check!(certificate), "A required value is missing!");
        Self { sign_value, public_key, certificate }
    }
}

// ==========================================================================
// Quoate Result
// ==========================================================================

/// Contains the result of a cryptographic quoting operation.
///
/// Instances of this struct are returned by the [`FapiContext::quote()`](crate::FapiContext::quote) function.
#[non_exhaustive]
pub struct QuoteResult {
    pub quote_info: JsonValue,
    pub signature: Vec<u8>,
    pub prc_log: Option<JsonValue>,
    pub certificate: Option<String>,
}

impl QuoteResult {
    pub fn from(quote_info: JsonValue, signature: Vec<u8>, prc_log: Option<JsonValue>, certificate: Option<String>) -> Self {
        assert!(not_empty!(quote_info) && not_empty!(signature) && opt_check!(prc_log) && opt_check!(certificate), "A required value is missing!");
        Self { quote_info, signature, prc_log, certificate }
    }
}

// ==========================================================================
// TPM BLOBs
// ==========================================================================

/// Contains the public and/or private BLOBs of a TPM object.
///
/// Instances of this struct are returned by the [`FapiContext::get_tpm_blobs()`](crate::FapiContext::get_tpm_blobs) function.
#[non_exhaustive]
pub struct TpmBlobs {
    pub public_key: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub policy: Option<JsonValue>,
}

impl TpmBlobs {
    pub fn from(public_key: Option<Vec<u8>>, private_key: Option<Vec<u8>>, policy: Option<JsonValue>) -> Self {
        assert!(opt_check!(public_key) && opt_check!(private_key) && opt_check!(policy), "A required value is missing!");
        Self { public_key, private_key, policy }
    }
}
