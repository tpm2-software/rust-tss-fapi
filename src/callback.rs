/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use super::{HashAlgorithm, fapi_sys::TPM2_ALG_ID, memory::CStringHolder};
use log::trace;
use std::{any::Any, borrow::Cow, ffi::CStr, fmt::Debug};

// ==========================================================================
// Callback parameters
// ==========================================================================

/// The parameters that are provided to the [`FapiCallbacks::auth_cb`] callback.
#[derive(Debug)]
pub struct AuthCbParam<'a> {
    /// Identifies the TPM object (path) for which an authorization value is requested.
    pub object_path: &'a str,
    /// User readable description of the authorization value requested (optional).
    pub description: Option<&'a str>,
}

/// The parameters that are provided to the [`FapiCallbacks::sign_cb`] callback.
#[derive(Debug)]
pub struct SignCbParam<'a> {
    /// Identifies the policy (path) being executed for which a signature is requested.
    pub object_path: &'a str,
    /// Description as provided in the policy definition (optional).
    pub description: Option<&'a str>,
    /// The public key that will be used by the TPM to verify the signature, in PEM encoding.
    pub public_key: &'a str,
    /// Human readable information, regarding the public key to be used (optional).
    pub key_hint: Option<&'a str>,
    /// The hash algorithm to be used during signing.
    pub hash_algo: HashAlgorithm,
    /// The data that is to be hashed and signed by the application.
    pub challenge: &'a [u8],
}

/// The parameters that are provided to the [`FapiCallbacks::branch_cb`] callback.
#[derive(Debug)]
pub struct BranchCbParam<'a> {
    /// Identifies the policy (path) being executed for which a branch choice is requested.
    pub object_path: &'a str,
    /// Description as provided in the policy definition (optional).
    pub description: Option<&'a str>,
    /// A list of human readable names for the branches as from the *PolicyOR* statement.
    pub branches: Vec<&'a str>,
}

/// The parameters that are provided to the [`FapiCallbacks::policy_action_cb`] callback.
#[derive(Debug)]
pub struct PolicyActionCbParam<'a> {
    /// Identifies the policy (path) being executed for which an action is signaled.
    pub object_path: &'a str,
    /// The action string as specified in the PolicyAction (optional).
    pub action: Option<&'a str>,
}

impl<'a> AuthCbParam<'a> {
    fn new(object_path: &'a CStr, description: Option<&'a CStr>) -> Self {
        Self { object_path: object_path.to_str().unwrap_or_default(), description: description.map(|str| str.to_str().unwrap_or_default()) }
    }
}

impl<'a> SignCbParam<'a> {
    fn new(
        object_path: &'a CStr,
        description: Option<&'a CStr>,
        public_key: &'a CStr,
        key_hint: Option<&'a CStr>,
        hash_algo: u32,
        challenge: &'a [u8],
    ) -> Self {
        Self {
            object_path: object_path.to_str().unwrap_or_default(),
            description: description.map(|str| str.to_str().unwrap_or_default()),
            public_key: public_key.to_str().unwrap_or_default(),
            key_hint: key_hint.map(|str| str.to_str().unwrap_or_default()),
            hash_algo: HashAlgorithm::from_id(TPM2_ALG_ID::try_from(hash_algo).unwrap_or_default()),
            challenge,
        }
    }
}

impl<'a> BranchCbParam<'a> {
    fn new(object_path: &'a CStr, description: Option<&'a CStr>, branches: &'a [&CStr]) -> Self {
        Self {
            object_path: object_path.to_str().unwrap_or_default(),
            description: description.map(|str| str.to_str().unwrap_or_default()),
            branches: branches.iter().map(|str| str.to_str().unwrap_or_default()).collect(),
        }
    }
}

impl<'a> PolicyActionCbParam<'a> {
    fn new(object_path: &'a CStr, action: Option<&'a CStr>) -> Self {
        Self { object_path: object_path.to_str().unwrap_or_default(), action: action.map(|str| str.to_str().unwrap_or_default()) }
    }
}

// ==========================================================================
// AsAny trait
// ==========================================================================

/// Helper trait that provides the [`as_any()`](AsAny::as_any) and [`as_mut_any()`](AsAny::as_mut_any) functions.
pub trait AsAny: Any {
    /// A helper function that returns the implementation as a [`&dyn Any`](std::any::Any) reference.
    fn as_any(&self) -> &dyn Any;

    /// A helper function that returns the implementation as a [`&mut dyn Any`](std::any::Any) reference.
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

// ==========================================================================
// Callbacks trait
// ==========================================================================

/// Represents the set of application-defined callback functions that the FAPI invokes.
///
/// Implementations of this trait are registered with a FAPI context via the [**`FapiContext::set_callbacks()`**](crate::FapiContext::set_callbacks) function.
///
/// ### Example
///
/// Applications shall implement this trait as follows:
///
/// ```
/// #[derive(Debug)]
/// pub struct MyCallbacks;
///
/// impl FapiCallbacks for MyCallbacks {
///     fn auth_cb(&self, param: AuthCbParam) -> Option<Cow<'static, str>> {
///         /* ... */
///     }
///
///     fn sign_cb(&self, param: SignCbParam) -> Option<Vec<u8>> {
///         /* ... */
///     }
///
///     fn branch_cb(&self, param: BranchCbParam) -> Option<usize> {
///         /* ... */
///     }
///
///     fn policy_action_cb(&self, param: PolicyActionCbParam) -> bool {
///         /* ... */
///     }
/// }
/// ```
pub trait FapiCallbacks: AsAny + Send + Debug + 'static {
    /// A callback function that allows the FAPI to request authorization values.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetAuthCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_auth_c_b.html)
    fn auth_cb(&self, _param: AuthCbParam) -> Option<Cow<'static, str>> {
        None
    }

    /// A callback function that allows the FAPI to request signatures.
    ///
    /// Signatures are requested for authorizing TPM objects.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetSignCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn sign_cb(&self, _param: SignCbParam) -> Option<Vec<u8>> {
        None
    }

    /// A callback function that allows the FAPI to request branch choices.
    ///
    /// It is usually called during policy evaluation.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetBranchCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn branch_cb(&self, _param: BranchCbParam) -> Option<usize> {
        None
    }

    /// A callback function that allows the FAPI to notify the application.
    ///
    /// It is usually called to announce policy actions.
    ///
    /// The default implementation of this function returns `false`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetPolicyActionCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn policy_action_cb(&self, _param: PolicyActionCbParam) -> bool {
        false
    }
}

// ==========================================================================
// Callbacks manager
// ==========================================================================

#[derive(Debug)]
pub struct CallbackManager {
    inner: Box<dyn FapiCallbacks>,
    auth_value: Option<CStringHolder>,
    sign_data: Option<Vec<u8>>,
}

impl CallbackManager {
    pub fn new(callbacks: impl FapiCallbacks) -> Self {
        Self { inner: Box::new(callbacks), auth_value: None, sign_data: None }
    }

    pub fn clear(&mut self) {
        if self.auth_value.is_some() {
            self.auth_value = None;
        }
        if self.sign_data.is_some() {
            self.sign_data = None;
        }
    }

    pub fn into_inner(self) -> Box<dyn FapiCallbacks> {
        self.inner
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Callback functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    pub fn auth_cb(&mut self, object_path: &CStr, description: Option<&CStr>) -> Option<&CStringHolder> {
        let param = AuthCbParam::new(object_path, description);
        trace!("Callbacks::auth_cb({:?})", &param);
        match self.inner.auth_cb(param) {
            Some(value) => {
                self.auth_value = CStringHolder::try_from(value).ok();
                self.auth_value.as_ref()
            }
            _ => None,
        }
    }

    pub fn sign_cb(
        &mut self,
        object_path: &CStr,
        description: Option<&CStr>,
        public_key: &CStr,
        key_hint: Option<&CStr>,
        hash_algo: u32,
        challenge: &[u8],
    ) -> Option<&[u8]> {
        let param = SignCbParam::new(object_path, description, public_key, key_hint, hash_algo, challenge);
        trace!("Callbacks::sign_cb({:?})", &param);
        match self.inner.sign_cb(param) {
            Some(value) => {
                self.sign_data = Some(value);
                self.sign_data.as_deref()
            }
            _ => None,
        }
    }

    pub fn branch_cb(&mut self, object_path: &CStr, description: Option<&CStr>, branches: &[&CStr]) -> Option<usize> {
        let param = BranchCbParam::new(object_path, description, branches);
        trace!("Callbacks::branch_cb({:?})", &param);
        self.inner.branch_cb(param).inspect(|index| {
            if *index >= branches.len() {
                panic!("The chosen branch index #{} is out of range! (must be in the 0..{} range)", index, branches.len() - 1usize);
            }
        })
    }

    pub fn policy_action_cb(&mut self, object_path: &CStr, action: Option<&CStr>) -> bool {
        let param = PolicyActionCbParam::new(object_path, action);
        trace!("Callbacks::policy_action_cb({:?})", &param);
        self.inner.policy_action_cb(param)
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{AuthCbParam, BranchCbParam, FapiCallbacks, HashAlgorithm, PolicyActionCbParam, SignCbParam};
    use std::borrow::Cow;

    #[derive(Debug)]
    struct CallbackTest {
        password: &'static str,
    }

    impl FapiCallbacks for CallbackTest {
        fn auth_cb(&self, _param: super::AuthCbParam) -> Option<Cow<'static, str>> {
            Some(Cow::from(self.password))
        }

        fn sign_cb(&self, _param: super::SignCbParam) -> Option<Vec<u8>> {
            Some(b"\x01\x02\x03".to_vec())
        }

        fn branch_cb(&self, _param: super::BranchCbParam) -> Option<usize> {
            Some(1usize)
        }

        fn policy_action_cb(&self, _param: super::PolicyActionCbParam) -> bool {
            true
        }
    }

    #[test]
    fn test_callbacks() {
        let my_callbacks = CallbackTest { password: "my password" };
        my_callbacks.auth_cb(AuthCbParam { object_path: "/some/path", description: Some("some object") });
        my_callbacks.sign_cb(SignCbParam {
            object_path: "/some/path",
            description: Some("some object"),
            public_key: "key_data",
            key_hint: Some("key hint"),
            hash_algo: HashAlgorithm::Sha2_256,
            challenge: b"\x01\x02\x03",
        });
        my_callbacks.branch_cb(BranchCbParam { object_path: "/some/path", description: Some("some object"), branches: vec!["first", "second"] });
        my_callbacks.policy_action_cb(PolicyActionCbParam { object_path: "/some/path", action: Some("some action") });
    }
}

// ==========================================================================
// Callback entry points
// ==========================================================================

/// The "native" entry points that will be called by the FAPI directly.
pub mod entry_point {
    use super::{
        super::{
            fapi_sys::{
                TSS2_RC,
                constants::{self, TSS2_RC_SUCCESS},
            },
            memory::{ptr_to_cstr_vec, ptr_to_opt_cstr},
        },
        CallbackManager,
    };
    use std::{
        ffi::{CStr, c_char, c_void},
        slice,
    };

    /// Create FAPI error code from base error code
    macro_rules! mk_fapi_rc {
        ($error:ident) => {
            constants::TSS2_FEATURE_RC_LAYER | constants::$error
        };
    }

    /// Invokes the actual [`FapiCallbacks::auth_cb()`] function
    pub unsafe extern "C" fn auth_cb(object_path: *const c_char, description: *const c_char, auth: *mut *const c_char, user_data: *mut c_void) -> TSS2_RC {
        if object_path.is_null() || auth.is_null() || user_data.is_null() {
            return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
        }
        unsafe {
            match (*(user_data as *mut CallbackManager)).auth_cb(CStr::from_ptr(object_path), ptr_to_opt_cstr(description)) {
                Some(auth_value) => {
                    *auth = auth_value.as_ptr();
                    TSS2_RC_SUCCESS
                }
                _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
            }
        }
    }

    /// Invokes the actual [`FapiCallbacks::sign_cb()`] function
    pub unsafe extern "C" fn sign_cb(
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
        unsafe {
            match (*(user_data as *mut CallbackManager)).sign_cb(
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
    }

    /// Invokes the actual [`FapiCallbacks::branch_cb()`] function
    pub unsafe extern "C" fn branch_cb(
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
        unsafe {
            match (*(user_data as *mut CallbackManager)).branch_cb(
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
    }

    /// Invokes the actual [`FapiCallbacks::policy_action_cb()`] function
    pub unsafe extern "C" fn policy_action_cb(object_path: *const c_char, action: *const c_char, user_data: *mut c_void) -> TSS2_RC {
        if object_path.is_null() || user_data.is_null() {
            return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
        }
        unsafe {
            match (*(user_data as *mut CallbackManager)).policy_action_cb(CStr::from_ptr(object_path), ptr_to_opt_cstr(action)) {
                true => TSS2_RC_SUCCESS,
                _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
            }
        }
    }
}
