/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

use core::slice;
use json::{self, JsonValue};
use std::{
    ffi::{c_char, CStr},
    fmt::Display,
    num::NonZeroUsize,
    os::raw::c_void,
    ptr,
    sync::RwLock,
};

use crate::fapi_sys::{
    self,
    constants::{self, TSS2_RC_SUCCESS},
    FAPI_CONTEXT, TPM2_RC, TSS2_RC,
};
use crate::marshal::u64_from_be;
use crate::memory::{cond_out, cond_ptr, opt_to_len, opt_to_ptr, ptr_to_cstr_vec, ptr_to_opt_cstr, CStringHolder, FapiMemoryHolder};
use crate::{
    callback::{ActnCallback, AuthCallback, BranCallback, SignCallback},
    locking::LockGuard,
};
use crate::{flags::flags_to_string, BaseErrorCode, BlobType, ErrorCode, InternalError, KeyFlags, NvFlags, PaddingFlags, QuoteFlags, SealFlags};

/* Const */
const ERR_NO_RESULT_DATA: ErrorCode = ErrorCode::InternalError(InternalError::NoResultData);
const ERR_INVALID_ARGUMENTS: ErrorCode = ErrorCode::InternalError(InternalError::InvalidArguments);

/* Opaque type  */
type TctiOpaqueContextBlob = *mut [u8; 0];

/* Complex types */
type TpmBlobs = (Option<Vec<u8>>, Option<Vec<u8>>, Option<JsonValue>);
type SignResult = (Vec<u8>, Option<String>, Option<String>);
type QuoteResult = (JsonValue, Vec<u8>, Option<JsonValue>, Option<String>);

/// Wraps the native `FAPI_CONTEXT` and exposes the related FAPI functions.
///
/// Each FAPI context represents a logically independent connection to the TPM. It stores meta data information about object in order to calculate session auths and similar things.
///
/// A context is allocated and initialized using the [`new()`](FapiContext::new) function, while [dropping](std::ops::Drop) the object finalizes and de-allocates the context.
///
/// *See also:* [`FAPI_CONTEXT()`](https://tpm2-tss.readthedocs.io/en/latest/struct_f_a_p_i___c_o_n_t_e_x_t.html)
///
/// ### FAPI Specification
///
/// Most functions provided by `FapiContext` are direct equivalents of the underlying FAPI library functions.
///
/// For details, please refer to the TCG Feature API specification:  
/// <https://trustedcomputinggroup.org/wp-content/uploads/TSS_FAPI_v0p94_r09_pub.pdf>
///
/// ### Optional Parameters
///
/// Some FAPI function have *optional* input parameters. These parameters are represented as [`Option<T>`] on the Rust layer and they may be set to `None`, if they are **not** needed for a certain use-case. Set to `Some(value)`, if the parameter is actually used.
///
/// ### Return Values
///
/// The FAPI functions have a return type of [`Result<T, ErrorCode>`] on the Rust layer. If the underlying native FAPI invocation has succeeded, then the variant `Ok(_)` wrapping the actual return value(s) is returned. Otherwise, if an error has occurred, the variant `Err(error)` containing the relevant error code is returned. Please refer to the [ErrorCode](crate::ErrorCode) enumeration for details!
///
/// Some FAPI functions have *optional* return values (output parameters). On the rust layer, the call flags control whether these optional outputs shall be requested. The corresponding return values have type [`Option<T>`] and will be `None` if unavailable.
///
/// ### Thread Safety
///
/// `FapiContext` implements the `Send` trait, so it may be transferred to another thread. However, it does **not** implement the `Sync` trait! Hence, in order to share a `FapiContext` between multiple concurrent threads, wrapping the context in an `Arc<Mutex<_>>` is required. This effectively ensures that *at most* **one** thread at a time can access the "shared" `FapiContext`.
///
/// ### FAPI Library
///
/// The `tss2-fapi-rs` wrapper requires that the *native* TSS2 2.0 FAPI library, e.g. `libtss2-fapi.so`, is available at runtime.
///
/// Please refer to the section [*prerequisites*](./index.html#prerequisites) in the module-level documentation for more details!
///
/// ### FAPI Configuration
///
/// The FAPI context *implicitly* uses the local FAPI configuration (e.g. `fapi-config.json`).
///
/// Please set the environment variable **`TSS2_FAPICONF`** *before* creating a new FAPI context in order to change the path of the configuration file to be used by the TSS2 2.0 FAPI library. Otherwise, FAPI will fall back to the default path!
///
/// A template for creating the FAPI configuration is provided in the `tests/data` directory, but a valid configuration is probably already available, if you installed the native TSS2 2.0 FAPI library via the operating system's package manager.
///
/// ### FAPI Logging
///
/// FAPI logging can be controlled by the environment variable **`TSS2_LOG`**, which can be useful for debugging purposes.
///
/// Please set `TSS2_LOG` *before* creating a new FAPI context in order to change the log level of the TSS2 2.0 FAPI library. For example, set this variable to `all+debug` for more verbose outputs. A value of `all+none` will silence all debug outputs.
#[derive(Debug)]
pub struct FapiContext {
    native_holder: NativeContextHolder,
    callback_auth: Option<Box<AuthCallback>>,
    callback_sign: Option<Box<SignCallback>>,
    callback_bran: Option<Box<BranCallback>>,
    callback_actn: Option<Box<ActnCallback>>,
}

/// A struct that wraps the native C pointer to the underlying FAPI_CONTEXT instance
#[derive(Debug)]
pub struct NativeContextHolder {
    native_context: *mut FAPI_CONTEXT,
}

/// Lock for serializing certain FAPI calls
static FAPI_CALL_RWLOCK: RwLock<()> = RwLock::new(());

// ==========================================================================
// Helper functions
// ==========================================================================

/// Create FAPI error code from base error code
macro_rules! mk_fapi_rc {
    ($error:ident) => {
        constants::TSS2_FEATURE_RC_LAYER | constants::$error
    };
}

/// Assert that the given slice or slices are not empty
macro_rules! fail_if_empty {
    ($slice:ident) => {
        if <[_]>::is_empty($slice) {
            return Err(ERR_INVALID_ARGUMENTS);
        }
    };
    ($slice:ident, $($next_slice:ident),+) => {
        fail_if_empty!($slice);
        fail_if_empty!($($next_slice),+)
    }
}

/// Assert that the given optional slice or slices are not empty (they may be None though!)
macro_rules! fail_if_opt_empty {
    ($opt_slice:ident) => {
        if let Some(slice) = $opt_slice.as_ref() {
            fail_if_empty!(slice);
        }
    };
    ($opt_slice:ident, $($next_opt_slice:ident),+) => {
        fail_if_opt_empty!($opt_slice);
        fail_if_opt_empty!($($next_opt_slice),+)
    }
}

/// Create result from `TPM2_RC` error code
fn create_result_from_retval(error_code: TPM2_RC) -> Result<(), ErrorCode> {
    match error_code {
        TSS2_RC_SUCCESS => Ok(()),
        _ => Err(ErrorCode::from_raw(error_code)),
    }
}

// ==========================================================================
// Context implementation
// ==========================================================================

impl FapiContext {
    /// Creates and initializes a `FAPI_CONTEXT` that holds all the state and metadata information during an interaction with the TPM.
    ///
    /// *See also:* [`Fapi_Initialize()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___initialize.html)
    pub fn new() -> Result<Self, ErrorCode> {
        let mut native_context: *mut FAPI_CONTEXT = ptr::null_mut();
        create_result_from_retval(unsafe { fapi_sys::Fapi_Initialize(&mut native_context, ptr::null()) }).map(|_| Self {
            native_holder: NativeContextHolder::new(native_context),
            callback_auth: None,
            callback_sign: None,
            callback_bran: None,
            callback_actn: None,
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Callback setters
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// This function registers an application-defined function as a callback to allow the FAPI to request authorization values from the application. The callback is implemented via the [`AuthCallback`](crate::AuthCallback) struct.
    ///
    /// *See also:* [`Fapi_SetAuthCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_auth_c_b.html)
    pub fn set_auth_callback(&mut self, auth_callback: AuthCallback) -> Result<(), ErrorCode> {
        let mut callback_box = Box::new(auth_callback);
        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetAuthCB(
                context,
                Some(auth_callback_entrypoint),
                callback_box.as_mut() as *mut AuthCallback as *mut c_void,
            )
        })
        .map(|_| {
            self.callback_auth = Some(callback_box); /*store AuthCallback in FapiContext to keep it alive!*/
        })
    }

    /// This function registers an application-defined function as a callback to allow the FAPI to request signatures for authorizing the use of TPM objects from the application. The callback is implemented via the [`SignCallback`](crate::SignCallback) struct.
    ///
    /// *See also:* [`Fapi_SetSignCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    pub fn set_sign_callback(&mut self, sign_callback: SignCallback) -> Result<(), ErrorCode> {
        let mut callback_box = Box::new(sign_callback);
        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetSignCB(
                context,
                Some(sign_callback_entrypoint),
                callback_box.as_mut() as *mut SignCallback as *mut c_void,
            )
        })
        .map(|_| {
            self.callback_sign = Some(callback_box); /*store SignCallback in FapiContext to keep it alive!*/
        })
    }

    /// This function registers an application-defined function as a callback to allow the FAPI to request branch choices from the application during policy evaluation. The callback is implemented via the [`BranCallback`](crate::BranCallback) struct.
    ///
    /// *See also:* [`Fapi_SetBranchCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    pub fn set_branch_callback(&mut self, bran_callback: BranCallback) -> Result<(), ErrorCode> {
        let mut callback_box = Box::new(bran_callback);
        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetBranchCB(
                context,
                Some(branch_callback_entrypoint),
                callback_box.as_mut() as *mut BranCallback as *mut c_void,
            )
        })
        .map(|_| {
            self.callback_bran = Some(callback_box); /*store BranCallback in FapiContext to keep it alive!*/
        })
    }

    /// This function registers an application-defined function as a callback to allow the FAPI to notify the application about policy actions. The callback is implemented via the [`ActnCallback`](crate::ActnCallback) struct.
    ///
    /// *See also:* [`Fapi_SetPolicyActionCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    pub fn set_policy_action_callback(&mut self, actn_callback: ActnCallback) -> Result<(), ErrorCode> {
        let mut callback_box = Box::new(actn_callback);
        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetPolicyActionCB(
                context,
                Some(action_callback_entrypoint),
                callback_box.as_mut() as *mut ActnCallback as *mut c_void,
            )
        })
        .map(|_| {
            self.callback_actn = Some(callback_box); /*store BranCallback in FapiContext to keep it alive!*/
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Provisioning
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Provisions a TSS with its TPM. This includes the setting of important passwords and policy settings as well as the readout of the EK and its certificate and the initialization of the system-wide keystore.
    ///
    /// *See also:* [`Fapi_Provision()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___provision.html)
    pub fn provision(&mut self, auth_eh: Option<&str>, auth_sh: Option<&str>, auth_lo: Option<&str>) -> Result<(), ErrorCode> {
        let cstr_eh = CStringHolder::try_from(auth_eh)?;
        let cstr_sh = CStringHolder::try_from(auth_sh)?;
        let cstr_lo = CStringHolder::try_from(auth_lo)?;

        self.fapi_call(true, |context| unsafe {
            fapi_sys::Fapi_Provision(context, cstr_eh.as_ptr(), cstr_sh.as_ptr(), cstr_lo.as_ptr())
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Miscellaneous functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Returns a JSON value that identifies the versions of FAPI, TPM, configurations and other relevant information.
    ///
    /// *See also:* [`Fapi_GetInfo()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___get_info.html)
    pub fn get_info(&mut self) -> Result<JsonValue, ErrorCode> {
        let mut tpm_info: *mut c_char = ptr::null_mut();
        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_GetInfo(context, &mut tpm_info) })
            .and_then(|_| FapiMemoryHolder::from_str(tpm_info).to_string().ok_or(ERR_NO_RESULT_DATA))
            .and_then(|info_data| json::parse(&info_data[..]).map_err(|_error| ERR_NO_RESULT_DATA))
    }

    /// Creates an array with a specified number of bytes. May execute the underlying TPM command multiple times if the requested number of bytes is too big.
    ///
    /// *See also:* [`Fapi_GetRandom()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___get_random.html)
    pub fn get_random(&mut self, length: NonZeroUsize) -> Result<Vec<u8>, ErrorCode> {
        let mut data_ptr: *mut u8 = ptr::null_mut();
        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_GetRandom(context, length.into(), &mut data_ptr) })
            .and_then(|_| FapiMemoryHolder::from_raw(data_ptr, length.into()).to_vec().ok_or(ERR_NO_RESULT_DATA))
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [Key and policy management functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Creates a key inside the TPM based on the Key type, using the supplied policy and authValue. The key is then stored either in the FAPI metadata store or the TPM.
    ///
    /// *See also:* [`Fapi_CreateKey()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___create_key.html)
    pub fn create_key(&mut self, key_path: &str, key_type: Option<&[KeyFlags]>, pol_path: Option<&str>, auth_val: Option<&str>) -> Result<(), ErrorCode> {
        fail_if_opt_empty!(key_type);

        let cstr_path = CStringHolder::try_from(key_path)?;
        let cstr_type = CStringHolder::try_from(flags_to_string(key_type)?)?;
        let cstr_poli = CStringHolder::try_from(pol_path)?;
        let cstr_auth = CStringHolder::try_from(auth_val)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_CreateKey(context, cstr_path.as_ptr(), cstr_type.as_ptr(), cstr_poli.as_ptr(), cstr_auth.as_ptr())
        })
    }

    /// Imports a JSON encoded policy, policy template or key and stores it at the given path.
    ///
    /// *See also:* [`Fapi_Import()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___import.html)
    pub fn import(&mut self, path: &str, data: &JsonValue) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let cstr_data = CStringHolder::try_from(data)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Import(context, cstr_path.as_ptr(), cstr_data.as_ptr())
        })
    }

    /// Duplicates the key pointed to by `key_to_duplicate`, inclduing all keys below it, and encrypts it using the public key pointed to by `new_parent_public_key`. The exported data will contain the re-wrapped key and then the JSON encoded policy.
    ///
    /// If the parameter `new_parent_public_key` is `None`, then the *public key* pointed to by `key_to_duplicate` will be exported.
    ///
    /// *See also:* [`Fapi_ExportKey()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___export_key.html)
    pub fn export_key(&mut self, key_to_duplicate: &str, new_parent_public_key: Option<&str>) -> Result<JsonValue, ErrorCode> {
        let cstr_duplicate = CStringHolder::try_from(key_to_duplicate)?;
        let cstr_publickey = CStringHolder::try_from(new_parent_public_key)?;
        let mut encoded_subtree: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_ExportKey(context, cstr_duplicate.as_ptr(), cstr_publickey.as_ptr(), &mut encoded_subtree)
        })
        .and_then(|_| FapiMemoryHolder::from_str(encoded_subtree).to_string().ok_or(ERR_NO_RESULT_DATA))
        .and_then(|exported_data| json::parse(&exported_data[..]).map_err(|_error| ERR_NO_RESULT_DATA))
    }

    /// Exports a policy to a JSON encoded byte buffer.
    ///
    /// *See also:* [`Fapi_ExportPolicy()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___export_policy.html)
    pub fn export_policy(&mut self, path: &str) -> Result<JsonValue, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut policy: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_ExportPolicy(context, cstr_path.as_ptr(), &mut policy)
        })
        .and_then(|_| FapiMemoryHolder::from_str(policy).to_string().ok_or(ERR_NO_RESULT_DATA))
        .and_then(|exported_data| json::parse(&exported_data[..]).map_err(|_error| ERR_NO_RESULT_DATA))
    }

    /// Get the public and private BLOBs of a TPM object. They can be loaded with a lower-level API such as the SAPI or the ESAPI.
    ///
    /// The flags `get_pubkey`, `get_privkey` and `get_policy` control which BLOBs are requested. Even if a BLOB was requested, that BLOB may *not* be available, in which case a `None` value is returned.
    ///
    /// *See also:* [`Fapi_GetTpmBlobs()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_tpm_blobs.html)
    ///
    /// ###### Return Value
    ///
    /// **`(Option(public_key), Option(private_key), Option(policy))`**
    pub fn get_tpm_blobs(&mut self, key_path: &str, get_pubkey: bool, get_privkey: bool, get_policy: bool) -> Result<TpmBlobs, ErrorCode> {
        if !(get_pubkey || get_privkey || get_policy) {
            return Err(ERR_INVALID_ARGUMENTS); /* must request at least one kind of BLOB! */
        }

        let cstr_path = CStringHolder::try_from(key_path)?;

        let mut blob_pub_data: *mut u8 = ptr::null_mut();
        let mut blob_pub_size: usize = 0;
        let mut blob_sec_data: *mut u8 = ptr::null_mut();
        let mut blob_sec_size: usize = 0;
        let mut policy_string: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetTpmBlobs(
                context,
                cstr_path.as_ptr(),
                cond_out(&mut blob_pub_data, get_pubkey),
                cond_ptr(&mut blob_pub_size, get_pubkey),
                cond_out(&mut blob_sec_data, get_privkey),
                cond_ptr(&mut blob_sec_size, get_privkey),
                cond_out(&mut policy_string, get_policy),
            )
        })
        .map(|_| {
            (
                FapiMemoryHolder::from_raw(blob_pub_data, blob_pub_size).to_vec(),
                FapiMemoryHolder::from_raw(blob_sec_data, blob_sec_size).to_vec(),
                FapiMemoryHolder::from_str(policy_string).to_json(),
            )
        })
    }

    /// Gets blobs of FAPI objects which can be used to create ESAPI objects.
    ///
    /// *See also:* [`Fapi_GetEsysBlob()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_esys_blobs.html)
    pub fn get_esys_blob(&mut self, path: &str) -> Result<(BlobType, Vec<u8>), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut blob_type: u8 = 0;
        let mut blob_data: *mut u8 = ptr::null_mut();
        let mut blob_size: usize = 0;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetEsysBlob(context, cstr_path.as_ptr(), &mut blob_type, &mut blob_data, &mut blob_size)
        })
        .and_then(|_| FapiMemoryHolder::from_raw(blob_data, blob_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
        .and_then(|esys_blob| {
            BlobType::try_from(blob_type)
                .map(|type_flag| (type_flag, esys_blob))
                .map_err(|_| ERR_NO_RESULT_DATA)
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ NV index functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// This command creates an NV index in the TPM using a given path and type.
    ///
    /// *See also:* [`Fapi_CreateNv()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___create_nv.html)
    pub fn create_nv(
        &mut self,
        nv_path: &str,
        nvi_type: Option<&[NvFlags]>,
        nvi_size: usize,
        pol_path: Option<&str>,
        auth_val: Option<&str>,
    ) -> Result<(), ErrorCode> {
        fail_if_opt_empty!(nvi_type);

        let cstr_path = CStringHolder::try_from(nv_path)?;
        let cstr_type = CStringHolder::try_from(flags_to_string(nvi_type)?)?;
        let cstr_poli = CStringHolder::try_from(pol_path)?;
        let cstr_auth = CStringHolder::try_from(auth_val)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_CreateNv(
                context,
                cstr_path.as_ptr(),
                cstr_type.as_ptr(),
                nvi_size,
                cstr_poli.as_ptr(),
                cstr_auth.as_ptr(),
            )
        })
    }

    /// Reads data from an NV index within the TPM.
    ///
    /// The flag `request_log` controls whether the log data shall be requested, if the NV index was created as "pcr" type.
    ///
    /// *See also:* [`Fapi_NvRead()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_read.html)
    ///
    /// ###### Return Value
    ///
    /// **`(nv_data, Option(log_data))`**
    pub fn nv_read(&mut self, nv_path: &str, request_log: bool) -> Result<(Vec<u8>, Option<JsonValue>), ErrorCode> {
        let cstr_path = CStringHolder::try_from(nv_path)?;
        let mut data: *mut u8 = ptr::null_mut();
        let mut size: usize = 0;
        let mut logs: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_NvRead(context, cstr_path.as_ptr(), &mut data, &mut size, cond_out(&mut logs, request_log))
        })
        .and_then(|_| FapiMemoryHolder::from_raw(data, size).to_vec().ok_or(ERR_NO_RESULT_DATA))
        .map(|result| (result, FapiMemoryHolder::from_str(logs).to_json()))
    }

    /// Convenience function to [`nv_read()`](FapiContext::nv_read) an **`u64`** value. Assumes "big endian" byte order.
    ///
    /// *See also:* [`Fapi_NvRead()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_read.html)
    pub fn nv_read_u64(&mut self, nv_path: &str) -> Result<u64, ErrorCode> {
        self.nv_read(nv_path, false).map(|data| u64_from_be(&data.0[..]))
    }

    /// Writes data to an "ordinary" (i.e *not* pin, extend or counter) NV index.
    ///
    /// *See also:* [`Fapi_NvWrite()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_write.html)
    pub fn nv_write(&mut self, nv_path: &str, data: &[u8]) -> Result<(), ErrorCode> {
        fail_if_empty!(data);
        let cstr_path = CStringHolder::try_from(nv_path)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_NvWrite(context, cstr_path.as_ptr(), data.as_ptr(), data.len())
        })
    }

    /// Convenience function to [`nv_write()`](FapiContext::nv_write) an **`u64`** value. Assumes "big endian" byte order.
    ///
    /// *See also:* [`Fapi_NvWrite()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_write.html)
    pub fn nv_write_u64(&mut self, nv_path: &str, value: u64) -> Result<(), ErrorCode> {
        self.nv_write(nv_path, &value.to_be_bytes()[..])
    }

    /// Increments an NV index that is a counter by 1.
    ///
    /// *See also:* [`Fapi_NvIncrement()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_increment.html)
    pub fn nv_increment(&mut self, nv_path: &str) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(nv_path)?;

        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_NvIncrement(context, cstr_path.as_ptr()) })
    }

    /// Sets bits in an NV index that was created as a bit field. Any number of bits from 0 to 64 may be SET.
    ///
    /// *See also:* [`Fapi_NvSetBits()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___nv_set_bits.html)
    pub fn nv_set_bits(&mut self, nv_path: &str, bitmap: u64) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(nv_path)?;

        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_NvSetBits(context, cstr_path.as_ptr(), bitmap) })
    }

    /// Performs an extend operation on an NV index that was created as "pcr" type.
    ///
    /// *See also:* [`Fapi_NvExtend()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___nv_extend.html)
    pub fn nv_extend(&mut self, nv_path: &str, data: &[u8], log_data: Option<&JsonValue>) -> Result<(), ErrorCode> {
        fail_if_empty!(data);

        let cstr_path = CStringHolder::try_from(nv_path)?;
        let cstr_logs = CStringHolder::try_from(log_data)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_NvExtend(context, cstr_path.as_ptr(), data.as_ptr(), data.len(), cstr_logs.as_ptr())
        })
    }

    /// Write the policyDigest of a policy to an NV index so it can be used in policies containing PolicyAuthorizeNV elements.
    ///
    /// *See also:* [`Fapi_WriteAuthorizeNv()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___write_authorize_nv.html)
    pub fn write_authorize_nv(&mut self, nv_path: &str, pol_path: &str) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(nv_path)?;
        let cstr_poli = CStringHolder::try_from(pol_path)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_WriteAuthorizeNv(context, cstr_path.as_ptr(), cstr_poli.as_ptr())
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ PCR functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Performs an extend operation on a given PCR.
    ///
    /// *See also:* [`Fapi_PcrExtend()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___pcr_extend.html)
    pub fn pcr_extend(&mut self, pcr_no: u32, data: &[u8], log_data: Option<&str>) -> Result<(), ErrorCode> {
        fail_if_empty!(data);

        let cstr_logs = CStringHolder::try_from(log_data)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_PcrExtend(context, pcr_no, data.as_ptr(), data.len(), cstr_logs.as_ptr())
        })
    }

    /// Reads from a given PCR and returns the value and the event log.
    ///
    /// The flags `request_log` controls whether a PCR log shall be requested too.
    ///
    /// *See also:* [`Fapi_PcrRead()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___pcr_read.html)
    ///
    /// ###### Return Value
    ///
    /// **`(pcr_value, Option(prc_log))`**
    pub fn pcr_read(&mut self, pcr_no: u32, request_log: bool) -> Result<(Vec<u8>, Option<JsonValue>), ErrorCode> {
        let mut pcr_data: *mut u8 = ptr::null_mut();
        let mut pcr_size: usize = 0usize;
        let mut log_data: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_PcrRead(context, pcr_no, &mut pcr_data, &mut pcr_size, cond_out(&mut log_data, request_log))
        })
        .and_then(|_| FapiMemoryHolder::from_raw(pcr_data, pcr_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
        .map(|result| (result, FapiMemoryHolder::from_str(log_data).to_json()))
    }

    /// Given a set of PCRs and a restricted signing key, it will sign those PCRs and return the quote.
    ///
    /// The optional `qualifying_data` is a nonce provided by the caller to ensure freshness of the signature.
    ///
    /// The flags `request_log` and `request_cert` control whether to request PCR log and/or certificate. Even if requested, a signer certificate may *not* be available, in which case a `None` value is returned.
    ///
    /// *See also:* [`Fapi_Quote()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___quote.html)
    ///
    /// ###### Return Value
    ///
    /// **`(quote_info, signature, Option(prc_log), Option(certificate))`**
    pub fn quote(
        &mut self,
        pcr_no: &[u32],
        quote_type: Option<&[QuoteFlags]>,
        key_path: &str,
        qualifying_data: Option<&[u8]>,
        request_log: bool,
        request_cert: bool,
    ) -> Result<QuoteResult, ErrorCode> {
        fail_if_empty!(pcr_no);
        fail_if_opt_empty!(quote_type, qualifying_data);

        let cstr_path = CStringHolder::try_from(key_path)?;
        let cstr_type = CStringHolder::try_from(flags_to_string(quote_type)?)?;

        let mut quote_info: *mut c_char = ptr::null_mut();
        let mut signature_data: *mut u8 = ptr::null_mut();
        let mut signature_size = 0usize;
        let mut pcr_log: *mut c_char = ptr::null_mut();
        let mut certificate: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Quote(
                context,
                pcr_no.as_ptr() as *mut u32,
                pcr_no.len(),
                cstr_path.as_ptr(),
                cstr_type.as_ptr(),
                opt_to_ptr(qualifying_data),
                opt_to_len(qualifying_data),
                &mut quote_info,
                &mut signature_data,
                &mut signature_size,
                cond_out(&mut pcr_log, request_log),
                cond_out(&mut certificate, request_cert),
            )
        })
        .and_then(|_| FapiMemoryHolder::from_str(quote_info).to_json().ok_or(ERR_NO_RESULT_DATA))
        .and_then(|info| {
            FapiMemoryHolder::from_raw(signature_data, signature_size)
                .to_vec()
                .map(|data| (info, data))
                .ok_or(ERR_NO_RESULT_DATA)
        })
        .map(|signature| {
            (
                signature.0,
                signature.1,
                FapiMemoryHolder::from_str(pcr_log).to_json(),
                FapiMemoryHolder::from_str(certificate).to_string(),
            )
        })
    }

    /// Verifies that the data returned by a quote is valid. This includes:
    /// - Reconstructing the `quote_info`’s PCR values from the `prc_log` (if a `prc_log` was provided)
    /// - Verifying the `quote_info` using the signature and the public key at `key_path`
    ///
    /// *See also:* [`Fapi_VerifyQuote()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___verify_quote.html)
    pub fn verify_quote(
        &mut self,
        key_path: &str,
        qualifying_data: Option<&[u8]>,
        quote_info: &JsonValue,
        signature: &[u8],
        prc_log: Option<&JsonValue>,
    ) -> Result<bool, ErrorCode> {
        fail_if_empty!(signature);
        fail_if_opt_empty!(qualifying_data);

        let cstr_path = CStringHolder::try_from(key_path)?;
        let cstr_info = CStringHolder::try_from(quote_info)?;
        let cstr_logs = CStringHolder::try_from(prc_log)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_VerifyQuote(
                context,
                cstr_path.as_ptr(),
                opt_to_ptr(qualifying_data),
                opt_to_len(qualifying_data),
                cstr_info.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                cstr_logs.as_ptr(),
            )
        })
        .map(|_| true)
        .or_else(|error| match error {
            ErrorCode::FapiError(BaseErrorCode::GeneralFailure) => Ok(false),
            ErrorCode::FapiError(BaseErrorCode::SignatureVerificationFailed) => Ok(false),
            _ => Err(error),
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Encryption/decryption functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Encrypt the provided data for the target key using the TPM encryption schemes as specified in the crypto profile. This function does not use the TPM; i.e. works in non-TPM mode.
    ///
    /// *See also:* [`Fapi_Encrypt()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___encrypt.html)
    pub fn encrypt(&mut self, key_path: &str, plaintext: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        fail_if_empty!(plaintext);

        let cstr_path = CStringHolder::try_from(key_path)?;

        let mut ciphertext_data: *mut u8 = ptr::null_mut();
        let mut ciphertext_size: usize = 0;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Encrypt(
                context,
                cstr_path.as_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut ciphertext_data,
                &mut ciphertext_size,
            )
        })
        .and_then(|_| FapiMemoryHolder::from_raw(ciphertext_data, ciphertext_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
    }

    /// Decrypts data that was previously encrypted with [`encrypt()`](FapiContext::decrypt).
    ///
    /// *See also:* [`Fapi_Decrypt()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___decrypt.html)
    pub fn decrypt(&mut self, key_path: &str, ciphertext: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        fail_if_empty!(ciphertext);

        let cstr_path = CStringHolder::try_from(key_path)?;

        let mut plaintext_data: *mut u8 = ptr::null_mut();
        let mut plaintext_size: usize = 0;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Decrypt(
                context,
                cstr_path.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &mut plaintext_data,
                &mut plaintext_size,
            )
        })
        .and_then(|_| FapiMemoryHolder::from_raw(plaintext_data, plaintext_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Signature functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Uses a key, identified by its path, to sign a digest and puts the result in a TPM2B bytestream.
    ///
    /// The flags `get_pubkey` and `get_cert` control whether the signer's public key and/or the signer certificate shall be returned. If requested, a signer certificate may *not* be available, in which case a `None` value is returned.
    ///
    /// Note that this function can **not** sign the "plain" message! Use, e.g., the [`sha2`](https://crates.io/crates/sha2) crate for computing the digest to be signed!
    ///
    /// *See also:* [`Fapi_Sign()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___sign.html)
    ///
    /// ###### Return Value
    ///
    /// **`(signature_value, Option(public_key), Option(certificate))`**
    pub fn sign(
        &mut self,
        key_path: &str,
        pad_algo: Option<&[PaddingFlags]>,
        digest: &[u8],
        get_pubkey: bool,
        get_cert: bool,
    ) -> Result<SignResult, ErrorCode> {
        fail_if_empty!(digest);

        let cstr_path = CStringHolder::try_from(key_path)?;
        let cstr_algo = CStringHolder::try_from(flags_to_string(pad_algo)?)?;

        let mut signature_data: *mut u8 = ptr::null_mut();
        let mut signature_size: usize = 0;
        let mut public_key_pem: *mut c_char = ptr::null_mut();
        let mut signer_crt_pem: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Sign(
                context,
                cstr_path.as_ptr(),
                cstr_algo.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                &mut signature_data,
                &mut signature_size,
                cond_out(&mut public_key_pem, get_pubkey),
                cond_out(&mut signer_crt_pem, get_cert),
            )
        })
        .and_then(|_| FapiMemoryHolder::from_raw(signature_data, signature_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
        .map(|signature| {
            (
                signature,
                FapiMemoryHolder::from_str(public_key_pem).to_string(),
                FapiMemoryHolder::from_str(signer_crt_pem).to_string(),
            )
        })
    }

    /// Verifies a signature using a public key found in a keyPath.
    ///
    /// Returns `Ok(true)` if the signature is *valid*, `Ok(false)` if the signature is *invalid* (or malformed), and `Err(_)` if an error other than the signature value being invalid (or malformed) occurred during the verification process.
    ///
    /// *See also:* [`Fapi_VerifySignature()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___verify_signature.html)
    pub fn verify_signature(&mut self, key_path: &str, digest: &[u8], signature: &[u8]) -> Result<bool, ErrorCode> {
        fail_if_empty!(digest, signature);

        let cstr_path = CStringHolder::try_from(key_path)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_VerifySignature(context, cstr_path.as_ptr(), digest.as_ptr(), digest.len(), signature.as_ptr(), signature.len())
        })
        .map(|_| true)
        .or_else(|error| match error {
            ErrorCode::FapiError(BaseErrorCode::GeneralFailure) => Ok(false),
            ErrorCode::FapiError(BaseErrorCode::SignatureVerificationFailed) => Ok(false),
            _ => Err(error),
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Sealing functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Creates a sealed object and stores it in the FAPI metadata store. If no data is provided, the TPM generates random data to fill the sealed object.
    ///
    /// *See also:* [`Fapi_CreateSeal()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___create_seal.html)
    pub fn create_seal(
        &mut self,
        path: &str,
        seal_type: Option<&[SealFlags]>,
        seal_size: NonZeroUsize,
        pol_path: Option<&str>,
        auth_val: Option<&str>,
        data: Option<&[u8]>,
    ) -> Result<(), ErrorCode> {
        fail_if_opt_empty!(seal_type);
        fail_if_opt_empty!(data);

        let cstr_path = CStringHolder::try_from(path)?;
        let cstr_type = CStringHolder::try_from(flags_to_string(seal_type)?)?;
        let cstr_poli = CStringHolder::try_from(pol_path)?;
        let cstr_auth = CStringHolder::try_from(auth_val)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_CreateSeal(
                context,
                cstr_path.as_ptr(),
                cstr_type.as_ptr(),
                seal_size.get(),
                cstr_poli.as_ptr(),
                cstr_auth.as_ptr(),
                opt_to_ptr(data),
            )
        })
    }

    /// Unseals data from a seal in the FAPI metadata store.
    ///
    /// *See also:* [`Fapi_Unseal()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___unseal.html)
    pub fn unseal(&mut self, path: &str) -> Result<Vec<u8>, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut sealed_size: usize = 0;
        let mut sealed_data: *mut u8 = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_Unseal(context, cstr_path.as_ptr(), &mut sealed_data, &mut sealed_size)
        })
        .and_then(|_| FapiMemoryHolder::from_raw(sealed_data, sealed_size).to_vec().ok_or(ERR_NO_RESULT_DATA))
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Certificate functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Gets an x.509 certificate for the key at a given path.
    ///
    /// *See also:* [`Fapi_GetCertificate()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_certificate.html)
    pub fn get_certificate(&mut self, path: &str) -> Result<Option<String>, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut cert_data_pem: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetCertificate(context, cstr_path.as_ptr(), &mut cert_data_pem)
        })
        .map(|_| FapiMemoryHolder::from_str(cert_data_pem).to_string())
        .or_else(|error| match error {
            ErrorCode::FapiError(BaseErrorCode::NoCert) => Ok(None),
            _ => Err(error),
        })
    }

    /// Sets an x509 cert into the path of a key.
    ///
    /// If the parameter `cert_data` is `None`, then an existing certificate will be removed from the entity.
    ///
    /// *See also:* [`Fapi_SetCertificate()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_certificate.html)
    pub fn set_certificate(&mut self, path: &str, cert_data: Option<&str>) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let cstr_cert = CStringHolder::try_from(cert_data)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetCertificate(context, cstr_path.as_ptr(), cstr_cert.as_ptr())
        })
    }

    /// Returns the set of Platform certificates concatenated in a continuous buffer, if the platform provides platform certificates. Platform certificates for TPM 2.0 can consist not only of a single certificate but also a series of so-called delta certificates.
    ///
    /// *See also:* [`Fapi_GetPlatformCertificates()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_platform_certificates.html)
    pub fn get_platform_certificates(&mut self) -> Result<Option<Vec<u8>>, ErrorCode> {
        let mut certificate_size: usize = 0;
        let mut certificate_data: *mut u8 = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetPlatformCertificates(context, &mut certificate_data, &mut certificate_size)
        })
        .and_then(|_| {
            FapiMemoryHolder::from_raw(certificate_data, certificate_size)
                .to_vec()
                .ok_or(ERR_NO_RESULT_DATA)
                .map(Some)
        })
        .or_else(|error| match error {
            ErrorCode::FapiError(BaseErrorCode::NoCert) => Ok(None),
            _ => Err(error),
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Description and associated data functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Returns the description of a previously stored object.
    ///
    /// *See also:* [`Fapi_GetDescription()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_description.html)
    pub fn get_description(&mut self, path: &str) -> Result<Option<String>, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut description: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetDescription(context, cstr_path.as_ptr(), &mut description)
        })
        .map(|_| FapiMemoryHolder::from_str(description).to_string())
    }

    /// Allows an application to assign a human readable description to an object in the metadata store.
    ///
    /// If the parameter `description` is `None`, then any stored description assigned to the referenced object is deleted.
    ///
    /// *See also:* [`Fapi_SetDescription()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_description.html)
    pub fn set_description(&mut self, path: &str, description: Option<&str>) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let cstr_desc = CStringHolder::try_from(description)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetDescription(context, cstr_path.as_ptr(), cstr_desc.as_ptr())
        })
    }

    /// Returns the previously stored application data for an object.
    ///
    /// *See also:* [`Fapi_GetAppData()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_app_data.html)
    pub fn get_app_data(&mut self, path: &str) -> Result<Option<Vec<u8>>, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut app_data_size: usize = 0;
        let mut app_data_buff: *mut u8 = ptr::null_mut();

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_GetAppData(context, cstr_path.as_ptr(), &mut app_data_buff, &mut app_data_size)
        })
        .map(|_| FapiMemoryHolder::from_raw(app_data_buff, app_data_size).to_vec())
    }

    /// Associates an arbitrary data blob with a given object.
    ///
    /// If the parameter `app_data` is `None`, then the stored data for the referenced object is erased.
    ///
    /// *See also:* [`Fapi_SetAppData()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_app_data.html)
    pub fn set_app_data(&mut self, path: &str, app_data: Option<&[u8]>) -> Result<(), ErrorCode> {
        fail_if_opt_empty!(app_data);
        let cstr_path = CStringHolder::try_from(path)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_SetAppData(context, cstr_path.as_ptr(), opt_to_ptr(app_data), opt_to_len(app_data))
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Enumeration and deletion functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Enumerates all objects in the metadatastore in a given path and returns them in a list of complete paths.
    ///
    /// *See also:* [`Fapi_List()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___list.html)
    pub fn list(&mut self, path: &str) -> Result<Vec<String>, ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let mut list: *mut c_char = ptr::null_mut();

        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_List(context, cstr_path.as_ptr(), &mut list) })
            .and_then(|_| {
                FapiMemoryHolder::from_str(list)
                    .to_string()
                    .map(|str| str.split(':').map(str::to_owned).collect())
                    .ok_or(ERR_NO_RESULT_DATA)
            })
    }

    /// Deletes a given key, policy or NV index from the system.
    ///
    /// *See also:* [`Fapi_Delete()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___delete.html)
    pub fn delete(&mut self, path: &str) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;

        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_Delete(context, cstr_path.as_ptr()) })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Auth functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Changes the authorization data of an entity found at key path. The parameter `auth` is a 0-terminated UTF-8 encoded password. If it is longer than the digest size of the entity's nameAlg, it will be hashed according the the TPM specification part 1, rev 138, section 19.6.4.3.
    ///
    /// If authValue is NULL then thep assword is set to the empty string.
    ///
    /// *See also:* [`Fapi_ChangeAuth()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___change_auth.html)
    pub fn change_auth(&mut self, path: &str, auth: Option<&str>) -> Result<(), ErrorCode> {
        let cstr_path = CStringHolder::try_from(path)?;
        let cstr_auth = CStringHolder::try_from(auth)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_ChangeAuth(context, cstr_path.as_ptr(), cstr_auth.as_ptr())
        })
    }

    /// If a current policy happens to be a PolicyAuthorize, then for it to be used, the user must first satisfy a policy authorized by a having been signed (and made into a ticket) by an authorized party.
    ///
    /// *See also:* [`Fapi_AuthorizePolicy()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___authorize_policy.html)
    pub fn authorize_policy(&mut self, pol_path: &str, key_path: &str, ref_data: Option<&[u8]>) -> Result<(), ErrorCode> {
        fail_if_opt_empty!(ref_data);

        let cstr_path_pol = CStringHolder::try_from(pol_path)?;
        let cstr_path_key = CStringHolder::try_from(key_path)?;

        self.fapi_call(false, |context| unsafe {
            fapi_sys::Fapi_AuthorizePolicy(
                context,
                cstr_path_pol.as_ptr(),
                cstr_path_key.as_ptr(),
                opt_to_ptr(ref_data),
                opt_to_len(ref_data),
            )
        })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Interoperability functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Returns the `TSS2_TCTI_CONTEXT` currently used by this `FAPI_CONTEXT`. The purpose is to enable advanced access to the TPM that is currently being talked to.
    ///
    /// *See also:* [`Fapi_GetTcti()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___get_tcti.html)
    pub fn get_tcti(&mut self) -> Result<TctiOpaqueContextBlob, ErrorCode> {
        let mut tcti: *mut fapi_sys::TSS2_TCTI_CONTEXT = ptr::null_mut();

        self.fapi_call(false, |context| unsafe { fapi_sys::Fapi_GetTcti(context, &mut tcti) })
            .map(|_| tcti as TctiOpaqueContextBlob)
    }

    /// Returns an array of handles that can be polled on to get notified when data from the TPM or from a disk operation is available.
    ///
    /// *See also:* [`Fapi_GetPollHandles()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___get_poll_handles.html)
    ///
    /// <div class="warning">
    ///
    /// This functions is a stub. Currently, `Fapi_GetPollHandles()` is **not** implemented in the Rust wrapper library!
    ///
    /// </div>
    pub fn get_poll_handles(&mut self) -> Result<Vec<()>, ErrorCode> {
        todo!("Not implemented yet.");
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // [ Internal functions ]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Wrapper function that performs the actual FAPI invocation and checks the return value
    /// If `exclusive` is *true*, then this call will be serialized
    fn fapi_call<F>(&mut self, exclusive: bool, caller: F) -> Result<(), ErrorCode>
    where
        F: FnOnce(*mut FAPI_CONTEXT) -> TSS2_RC,
    {
        let error_code = {
            let _guard = LockGuard::acquire(&FAPI_CALL_RWLOCK, exclusive);
            caller(self.native_holder.get())
        };
        self.clear_callbacks();
        create_result_from_retval(error_code)
    }

    /// Clear temporary buffers of the callback, e.g. after FAPI invocation
    fn clear_callbacks(&mut self) {
        if let Some(cb) = &mut self.callback_auth {
            cb.clear_buffer()
        }
        if let Some(cb) = &mut self.callback_sign {
            cb.clear_buffer()
        }
    }
}

impl Display for FapiContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FapiContext({:p})", self.native_holder.get())
    }
}

// ==========================================================================
// ContextHolder implementation
// ==========================================================================

impl NativeContextHolder {
    pub fn new(native_context: *mut FAPI_CONTEXT) -> Self {
        Self { native_context }
    }

    pub fn get(&self) -> *mut FAPI_CONTEXT {
        assert!(!self.native_context.is_null(), "FAPI_CONTEXT is a NULL pointer!");
        self.native_context
    }
}

/// Free the native `FAPI_CONTEXT` as soon as the holder goes out of scope!
impl Drop for NativeContextHolder {
    /// Finalizes a context by closing IPC/RPC connections and freeing its consumed memory.
    ///
    /// *See also:* [`Fapi_Finalize()`](https://tpm2-tss.readthedocs.io/en/latest/group___fapi___finalize.html)
    fn drop(&mut self) {
        unsafe {
            fapi_sys::Fapi_Finalize(&mut self.native_context);
            self.native_context = ptr::null_mut();
        }
    }
}

/// This allows `*mut FAPI_CONTEXT` to be moved between threads, but wrapping the `FapiContext` in an `Arc<Mutex<_>>` is still required!
unsafe impl Send for NativeContextHolder {}

// ==========================================================================
// Callback functions
// ==========================================================================

/// Invokes the actual AuthCallback struct
unsafe extern "C" fn auth_callback_entrypoint(
    object_path: *const c_char,
    description: *const c_char,
    auth: *mut *const c_char,
    user_data: *mut c_void,
) -> TSS2_RC {
    if object_path.is_null() || auth.is_null() || user_data.is_null() {
        return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
    }
    match (*(user_data as *mut AuthCallback)).invoke(CStr::from_ptr(object_path), ptr_to_opt_cstr(description)) {
        Some(auth_value) => {
            *auth = auth_value.as_ptr();
            TSS2_RC_SUCCESS
        }
        _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
    }
}

/// Invokes the actual SignCallback struct
unsafe extern "C" fn sign_callback_entrypoint(
    object_path: *const c_char,
    description: *const c_char,
    public_key: *const c_char,
    key_hint: *const c_char,
    hash_alg: u32,
    challenge_data: *const u8,
    challenge_size: usize,
    signature_data: *mut *const u8,
    signature_size: *mut usize,
    user_data: *mut c_void,
) -> TSS2_RC {
    if object_path.is_null()
        || public_key.is_null()
        || hash_alg == 0u32
        || challenge_data.is_null()
        || challenge_size == 0usize
        || signature_data.is_null()
        || signature_size.is_null()
        || user_data.is_null()
    {
        return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
    }
    match (*(user_data as *mut SignCallback)).invoke(
        CStr::from_ptr(object_path),
        ptr_to_opt_cstr(description),
        CStr::from_ptr(public_key),
        ptr_to_opt_cstr(key_hint),
        hash_alg,
        slice::from_raw_parts(challenge_data, challenge_size),
    ) {
        Some(sign_value) => {
            *signature_data = sign_value.as_ptr();
            *signature_size = sign_value.len();
            TSS2_RC_SUCCESS
        }
        _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
    }
}

/// Invokes the actual BranCallback struct
unsafe extern "C" fn branch_callback_entrypoint(
    object_path: *const c_char,
    description: *const c_char,
    branch_names: *mut *const c_char,
    num_branches: usize,
    selected: *mut usize,
    user_data: *mut c_void,
) -> TSS2_RC {
    if object_path.is_null() || branch_names.is_null() || num_branches == 0usize || selected.is_null() || user_data.is_null() {
        return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
    }
    match (*(user_data as *mut BranCallback)).invoke(
        CStr::from_ptr(object_path),
        ptr_to_opt_cstr(description),
        &ptr_to_cstr_vec(branch_names, num_branches)[..],
    ) {
        Some(bran_value) => {
            *selected = bran_value;
            TSS2_RC_SUCCESS
        }
        _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
    }
}

/// Invokes the actual ActnCallback struct
unsafe extern "C" fn action_callback_entrypoint(object_path: *const c_char, action: *const c_char, user_data: *mut c_void) -> TSS2_RC {
    if object_path.is_null() || user_data.is_null() {
        return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
    }
    match (*(user_data as *mut ActnCallback)).invoke(CStr::from_ptr(object_path), ptr_to_opt_cstr(action)) {
        true => TSS2_RC_SUCCESS,
        _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
    }
}
