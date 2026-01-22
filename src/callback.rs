/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use super::{
    HashAlgorithm,
    fapi_sys::TPM2_ALG_ID,
    memory::{CBinaryHolder, CStringHolder, CStringPointer, RawSlice},
};
use log::trace;
use std::{any::Any, borrow::Cow, ffi::CStr, fmt::Debug, sync::Mutex};

// ==========================================================================
// Callback parameters
// ==========================================================================

/// The parameters that are provided to the [`FapiCallbacks::auth_cb`] callback.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthCbParam<'a> {
    /// Identifies the TPM object (path) for which an authorization value is requested.
    pub object_path: &'a str,
    /// User readable description of the authorization value requested (optional).
    pub description: Option<&'a str>,
}

/// The parameters that are provided to the [`FapiCallbacks::sign_cb`] callback.
#[derive(Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
/// An implementation is **not** required to override *all* callback functions, as the trait provides “blank” default implementations.
///
/// Generally, an application overrides only the callback functions that it actually needs.
///
/// Implementations of this trait are registered with a FAPI context via the [**`FapiContext::set_callbacks()`**](crate::FapiContext::set_callbacks) function.
///
/// ### Example
///
/// Applications shall implement this trait as follows:
///
/// ```
/// pub struct MyCallbacks;
///
/// impl FapiCallbacks for MyCallbacks {
///     fn auth_cb(&mut self, param: AuthCbParam) -> Option<Cow<'static, str>> {
///         /* ... */
///     }
///
///     fn sign_cb(&mut self, param: SignCbParam) -> Option<Vec<u8>> {
///         /* ... */
///     }
///
///     fn branch_cb(&mut self, param: BranchCbParam) -> Option<usize> {
///         /* ... */
///     }
///
///     fn policy_action_cb(&mut self, param: PolicyActionCbParam) -> bool {
///         /* ... */
///     }
/// }
/// ```
pub trait FapiCallbacks: AsAny + Send + 'static {
    /// A callback function that allows the FAPI to request authorization values.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetAuthCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_auth_c_b.html)
    fn auth_cb(&mut self, _param: AuthCbParam) -> Option<Cow<'static, str>> {
        None
    }

    /// A callback function that allows the FAPI to request signatures.
    ///
    /// Signatures are requested for authorizing TPM objects.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetSignCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn sign_cb(&mut self, _param: SignCbParam) -> Option<Vec<u8>> {
        None
    }

    /// A callback function that allows the FAPI to request branch choices.
    ///
    /// It is usually called during policy evaluation.
    ///
    /// The default implementation of this function returns `None`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetBranchCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn branch_cb(&mut self, _param: BranchCbParam) -> Option<usize> {
        None
    }

    /// A callback function that allows the FAPI to notify the application.
    ///
    /// It is usually called to announce policy actions.
    ///
    /// The default implementation of this function returns `false`. Please override the function as needed!
    ///
    /// *See also:* [`Fapi_SetPolicyActionCB()`](https://tpm2-tss.readthedocs.io/en/stable/group___fapi___set_sign_c_b.html)
    fn policy_action_cb(&mut self, _param: PolicyActionCbParam) -> bool {
        false
    }
}

impl dyn FapiCallbacks {
    /// Downcast this `dyn FapiCallbacks` to a reference of the concrete type **`T`**.
    pub fn downcast<T: 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref()
    }

    /// Downcast this `dyn FapiCallbacks` to a mutable reference of the concrete type **`T`**.
    pub fn downcast_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.as_mut_any().downcast_mut()
    }
}

// ==========================================================================
// Callbacks implementation
// ==========================================================================

/// Provides a simple implementation of the [`FapiCallbacks`](crate::FapiCallbacks) trait.
#[allow(clippy::type_complexity)]
pub struct Callbacks {
    auth_fn: Box<dyn Fn(AuthCbParam) -> Option<Cow<'static, str>> + Send>,
    sign_fn: Box<dyn Fn(SignCbParam) -> Option<Vec<u8>> + Send>,
    branch_fn: Box<dyn Fn(BranchCbParam) -> Option<usize> + Send>,
    policy_action_fn: Box<dyn Fn(PolicyActionCbParam) -> bool + Send>,
}

impl Callbacks {
    /// Creates a new `Callbacks` instance with application-defined callback functions.
    ///
    /// Instances of this struct are registered with a FAPI context via the [**`FapiContext::set_callbacks()`**](crate::FapiContext::set_callbacks) function.
    pub fn new<AuthFn, SignFn, BranchFn, PolicyActionFn>(auth_fn: AuthFn, sign_fn: SignFn, branch_fn: BranchFn, policy_action_fn: PolicyActionFn) -> Self
    where
        AuthFn: Fn(AuthCbParam) -> Option<Cow<'static, str>> + Send + 'static,
        SignFn: Fn(SignCbParam) -> Option<Vec<u8>> + Send + 'static,
        BranchFn: Fn(BranchCbParam) -> Option<usize> + Send + 'static,
        PolicyActionFn: Fn(PolicyActionCbParam) -> bool + Send + 'static,
    {
        Self { auth_fn: Box::new(auth_fn), sign_fn: Box::new(sign_fn), branch_fn: Box::new(branch_fn), policy_action_fn: Box::new(policy_action_fn) }
    }

    /// Creates a `Callbacks` instance with an application-defined [`auth_cb`](crate::FapiCallbacks::auth_cb) callback function.
    ///
    /// All other callback functions will use the default implementation.
    pub fn with_auth<F>(auth_fn: F) -> Self
    where
        F: Fn(AuthCbParam) -> Option<Cow<'static, str>> + Send + 'static,
    {
        Self::new(auth_fn, |_| None, |_| None, |_| false)
    }

    /// Creates a `Callbacks` instance with an application-defined [`sign_cb`](crate::FapiCallbacks::sign_cb) callback function.
    ///
    /// All other callback functions will use the default implementation.
    pub fn with_sign<F>(sign_fn: F) -> Self
    where
        F: Fn(SignCbParam) -> Option<Vec<u8>> + Send + 'static,
    {
        Self::new(|_| None, sign_fn, |_| None, |_| false)
    }

    /// Creates a `Callbacks` instance with an application-defined [`branch_cb`](crate::FapiCallbacks::branch_cb) callback function.
    ///
    /// All other callback functions will use the default implementation.
    pub fn with_branch<F>(branch_fn: F) -> Self
    where
        F: Fn(BranchCbParam) -> Option<usize> + Send + 'static,
    {
        Self::new(|_| None, |_| None, branch_fn, |_| false)
    }

    /// Creates a `Callbacks` instance with an application-defined [`policy_action_cb`](crate::FapiCallbacks::policy_action_cb) callback function.
    ///
    /// All other callback functions will use the default implementation.
    pub fn with_policy_action<F>(policy_action_fn: F) -> Self
    where
        F: Fn(PolicyActionCbParam) -> bool + Send + 'static,
    {
        Self::new(|_| None, |_| None, |_| None, policy_action_fn)
    }
}

impl FapiCallbacks for Callbacks {
    fn auth_cb(&mut self, param: AuthCbParam) -> Option<Cow<'static, str>> {
        (self.auth_fn)(param)
    }

    fn sign_cb(&mut self, param: SignCbParam) -> Option<Vec<u8>> {
        (self.sign_fn)(param)
    }

    fn branch_cb(&mut self, param: BranchCbParam) -> Option<usize> {
        (self.branch_fn)(param)
    }

    fn policy_action_cb(&mut self, param: PolicyActionCbParam) -> bool {
        (self.policy_action_fn)(param)
    }
}

// ==========================================================================
// Temporary data holder
// ==========================================================================

/// Holds the temporary data to be returned to the FAPI by the callback
///
/// **Note:** We pass the return value from the application-defined callback function to the FAPI *as a pointer*, so we need to keep the actual object alive inside the `tss2-fapi-rs` layer, at least until the next FAPI function call, because otherwise we create a dangling pointer!
#[derive(Debug, Default)]
enum TemporaryData {
    #[default]
    Empty,
    String(CStringHolder),
    Data(CBinaryHolder),
}

impl TemporaryData {
    fn set_string(&mut self, string: CStringHolder) -> CStringPointer {
        *self = Self::String(string);
        match self {
            TemporaryData::String(string_ref) => string_ref.as_ptr(),
            _ => unreachable!(),
        }
    }

    fn set_data(&mut self, data: CBinaryHolder) -> RawSlice {
        *self = Self::Data(data);
        match self {
            TemporaryData::Data(data_ref) => data_ref.as_slice(),
            _ => unreachable!(),
        }
    }

    fn clear(&mut self) {
        *self = TemporaryData::Empty;
    }
}

// ==========================================================================
// Callbacks holder
// ==========================================================================

/// Holds the `FapiCallbacks` reference and the temporary buffers
struct CallbackHolder {
    callbacks: Box<dyn FapiCallbacks>,
    temp: TemporaryData,
}

impl CallbackHolder {
    fn new(callbacks: Box<dyn FapiCallbacks>) -> Self {
        Self { callbacks, temp: Default::default() }
    }
}

impl Debug for CallbackHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackHolder").field("callbacks", &self.callbacks.as_any().type_id()).field("temp", &self.temp).finish()
    }
}

// ==========================================================================
// Callbacks manager
// ==========================================================================

/// Internal struct that wraps the application-provided callbacks
#[derive(Debug)]
pub struct CallbackManager(Mutex<CallbackHolder>);

impl CallbackManager {
    pub fn new(callbacks: impl FapiCallbacks) -> Self {
        Self(Mutex::new(CallbackHolder::new(Box::new(callbacks))))
    }

    pub fn clear_temp(&self) {
        let mut lock = self.0.lock().unwrap();
        lock.temp.clear();
    }

    pub fn into_inner(self) -> Box<dyn FapiCallbacks> {
        self.0.into_inner().unwrap().callbacks
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Callback functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    fn auth_cb(&self, object_path: &CStr, description: Option<&CStr>) -> Option<CStringPointer> {
        let mut lock = self.0.lock().unwrap();
        let param = AuthCbParam::new(object_path, description);
        trace!("Callbacks::auth_cb({:?})", &param);
        lock.callbacks.auth_cb(param).and_then(|str| CStringHolder::try_from(str).ok()).map(|value| lock.temp.set_string(value))
    }

    fn sign_cb(
        &self,
        object_path: &CStr,
        description: Option<&CStr>,
        public_key: &CStr,
        key_hint: Option<&CStr>,
        hash_algo: u32,
        challenge: &[u8],
    ) -> Option<RawSlice> {
        let mut lock = self.0.lock().unwrap();
        let param = SignCbParam::new(object_path, description, public_key, key_hint, hash_algo, challenge);
        trace!("Callbacks::sign_cb({:?})", &param);
        lock.callbacks.sign_cb(param).and_then(|data| CBinaryHolder::try_from(data).ok()).map(|value| lock.temp.set_data(value))
    }

    fn branch_cb(&self, object_path: &CStr, description: Option<&CStr>, branches: &[&CStr]) -> Option<usize> {
        let mut lock = self.0.lock().unwrap();
        let param = BranchCbParam::new(object_path, description, branches);
        trace!("Callbacks::branch_cb({:?})", &param);
        lock.callbacks.branch_cb(param).inspect(|&index| {
            if index >= branches.len() {
                panic!("The chosen branch index #{} is out of range!", index);
            }
        })
    }

    fn policy_action_cb(&self, object_path: &CStr, action: Option<&CStr>) -> bool {
        let mut lock = self.0.lock().unwrap();
        let param = PolicyActionCbParam::new(object_path, action);
        trace!("Callbacks::policy_action_cb({:?})", &param);
        lock.callbacks.policy_action_cb(param)
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
        ptr, slice,
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
            let manager = &*(user_data as *const CallbackManager);
            let (auth_value, retval) = match manager.auth_cb(CStr::from_ptr(object_path), ptr_to_opt_cstr(description)) {
                Some(auth) => (auth, TSS2_RC_SUCCESS),
                _ => (ptr::null(), mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE)),
            };
            *auth = auth_value;
            retval
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
            let manager = &*(user_data as *const CallbackManager);
            let (sign_data_ptr, sign_data_len, retval) = match manager.sign_cb(
                CStr::from_ptr(object_path),
                ptr_to_opt_cstr(description),
                CStr::from_ptr(public_key),
                ptr_to_opt_cstr(key_hint),
                hash_alg,
                slice::from_raw_parts(challenge_data, challenge_size),
            ) {
                Some(sign_value) => (sign_value.data, sign_value.size, TSS2_RC_SUCCESS),
                _ => (ptr::null(), 0usize, mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE)),
            };
            *signature_data = sign_data_ptr;
            *signature_size = sign_data_len;
            retval
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
            let manager = &*(user_data as *const CallbackManager);
            let (selected_index, retval) =
                match manager.branch_cb(CStr::from_ptr(object_path), ptr_to_opt_cstr(description), &ptr_to_cstr_vec(branch_names, num_branches)[..]) {
                    Some(selected) => (selected, TSS2_RC_SUCCESS),
                    _ => (0usize, mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE)),
                };
            *selected = selected_index;
            retval
        }
    }

    /// Invokes the actual [`FapiCallbacks::policy_action_cb()`] function
    pub unsafe extern "C" fn policy_action_cb(object_path: *const c_char, action: *const c_char, user_data: *mut c_void) -> TSS2_RC {
        if object_path.is_null() || user_data.is_null() {
            return mk_fapi_rc!(TSS2_BASE_RC_BAD_VALUE);
        }
        unsafe {
            let manager = &*(user_data as *const CallbackManager);
            match manager.policy_action_cb(CStr::from_ptr(object_path), ptr_to_opt_cstr(action)) {
                true => TSS2_RC_SUCCESS,
                _ => mk_fapi_rc!(TSS2_BASE_RC_GENERAL_FAILURE),
            }
        }
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{AuthCbParam, BranchCbParam, FapiCallbacks, HashAlgorithm, PolicyActionCbParam, SignCbParam};
    use std::borrow::Cow;

    struct CallbackTest {
        password_str: &'static str,
        auth_paths: Vec<String>,
        sign_paths: Vec<String>,
        branch_paths: Vec<String>,
        action_paths: Vec<String>,
    }

    impl CallbackTest {
        pub fn new(password_str: &'static str) -> Self {
            Self { password_str, auth_paths: Vec::new(), sign_paths: Vec::new(), branch_paths: Vec::new(), action_paths: Vec::new() }
        }

        pub fn get_paths(&self) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
            (self.auth_paths.clone(), self.sign_paths.clone(), self.branch_paths.clone(), self.action_paths.clone())
        }
    }

    impl FapiCallbacks for CallbackTest {
        fn auth_cb(&mut self, param: super::AuthCbParam) -> Option<Cow<'static, str>> {
            self.auth_paths.push(param.object_path.to_owned());
            Some(Cow::from(self.password_str))
        }

        fn sign_cb(&mut self, param: super::SignCbParam) -> Option<Vec<u8>> {
            self.sign_paths.push(param.object_path.to_owned());
            Some(b"\x01\x02\x03".to_vec())
        }

        fn branch_cb(&mut self, param: super::BranchCbParam) -> Option<usize> {
            self.branch_paths.push(param.object_path.to_owned());
            Some(1usize)
        }

        fn policy_action_cb(&mut self, param: super::PolicyActionCbParam) -> bool {
            self.action_paths.push(param.object_path.to_owned());
            true
        }
    }

    #[test]
    fn test_callbacks() {
        let mut my_callbacks: Box<dyn FapiCallbacks> = Box::new(CallbackTest::new("my_password"));
        invoke_callbacks(&mut my_callbacks);

        let downcasted: &CallbackTest = my_callbacks.downcast().expect("Downcast failed!");
        let paths = downcasted.get_paths();

        assert_paths_eq(&paths.0, "/HS/SRK/my/auth/path");
        assert_paths_eq(&paths.1, "/HS/SRK/my/sign/path");
        assert_paths_eq(&paths.2, "/HS/SRK/my/bran/path");
        assert_paths_eq(&paths.3, "/HS/SRK/my/actn/path");
    }

    fn invoke_callbacks(callbacks: &mut Box<dyn FapiCallbacks>) {
        callbacks.auth_cb(AuthCbParam { object_path: "/HS/SRK/my/auth/path", description: Some("some object") });
        callbacks.sign_cb(SignCbParam {
            object_path: "/HS/SRK/my/sign/path",
            description: Some("some object"),
            public_key: "key_data",
            key_hint: Some("key hint"),
            hash_algo: HashAlgorithm::Sha2_256,
            challenge: b"\x01\x02\x03",
        });
        callbacks.branch_cb(BranchCbParam { object_path: "/HS/SRK/my/bran/path", description: Some("some object"), branches: vec!["first", "second"] });
        callbacks.policy_action_cb(PolicyActionCbParam { object_path: "/HS/SRK/my/actn/path", action: Some("some action") });
    }

    fn assert_paths_eq(paths: &[String], expected: &str) {
        assert_eq!(paths.iter().filter(|&str| str.eq(expected)).count(), 1usize);
        assert_eq!(paths.iter().filter(|&str| str.ne(expected)).count(), 0usize);
    }
}
