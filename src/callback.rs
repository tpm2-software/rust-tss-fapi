/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use crate::{fapi_sys::TPM2_ALG_ID, memory::CStringHolder, HashAlgorithm};
use log::trace;
use std::{any::Any, borrow::Cow, ffi::CStr, fmt::Debug};

// ==========================================================================
// AuthCallback
// ==========================================================================

/// A callback function that allows the FAPI to request authorization values.
///
/// Regsitered to a FAPI context via the [`set_auth_callback()`](crate::FapiContext::set_auth_callback) function.
pub struct AuthCallback {
    auth_fn: Box<AuthCallbackFunction>,
    auth_value: Option<CStringHolder>,
}

/// Signature of the wrapped [`AuthCallback`] function
type AuthCallbackFunction = dyn Fn(AuthCallbackParam) -> Option<Cow<'static, str>> + Send;

/// Wraps the parameters to be passed to the [`AuthCallback`] callback.
#[derive(Debug)]
pub struct AuthCallbackParam<'a> {
    /// Identifies the TPM object (path) for which an authorization value is requested.
    pub object_path: &'a str,
    /// User readable description of the authorization value requested (optional).
    pub description: Option<&'a str>,
}

impl AuthCallback {
    /// Creates a new callback instance.
    ///
    /// The supplied `auth_fn` will be called whenever the FAPI requests authorization values from the application. This function receives an [`AuthCallbackParam`] as parameter; it shall return `Some(value)`, if an authorization value for the requested object is provided by the application, or `None`, if **no** authorization value is provided.
    pub fn new(auth_fn: impl Fn(AuthCallbackParam) -> Option<Cow<'static, str>> + 'static + Send) -> Self {
        Self {
            auth_fn: Box::new(auth_fn),
            auth_value: None,
        }
    }

    /// Creates a new callback instance with additional data.
    ///
    /// The supplied `auth_fn` will be called whenever the FAPI requests authorization values from the application. This function receives an [`AuthCallbackParam`] as parameter; it shall return `Some(value)`, if an authorization value for the requested object is provided by the application, or `None`, if **no** authorization value is provided.
    ///
    /// The application-defined `extra_data` argument will be passed to each invocation of `auth_fn` as an additional parameter.
    pub fn with_data<T: 'static + Send>(sign_fn: impl Fn(AuthCallbackParam, &T) -> Option<Cow<'static, str>> + 'static + Send, extra_data: T) -> Self {
        Self::new(move |callback_param| sign_fn(callback_param, &extra_data))
    }

    /// Request authorization value for the specified TPM object (path) from the application.
    pub(crate) fn invoke(&mut self, object_path: &CStr, description: Option<&CStr>) -> Option<&CStringHolder> {
        let param = AuthCallbackParam::new(object_path, description);
        trace!("AuthCallback::invoke({:?})", &param);
        match (self.auth_fn)(param) {
            Some(value) => {
                self.auth_value = CStringHolder::try_from(value).ok();
                self.auth_value.as_ref()
            }
            _ => None,
        }
    }

    pub(crate) fn clear_buffer(&mut self) {
        self.auth_value.take();
    }
}

impl<'a> AuthCallbackParam<'a> {
    fn new(object_path: &'a CStr, description: Option<&'a CStr>) -> Self {
        Self {
            object_path: object_path.to_str().unwrap_or_default(),
            description: description.map(|str| str.to_str().unwrap_or_default()),
        }
    }
}

impl Debug for AuthCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCallback")
            .field("auth_fn", &(*self.auth_fn).type_id())
            .field("auth_value", &self.auth_value)
            .finish()
    }
}

// ==========================================================================
// SignCallback
// ==========================================================================

/// A callback function that allows the FAPI to request signatures.
///
/// Signatures are requested for authorizing TPM objects.
///
/// Registered to a FAPI context via the [`set_sign_callback()`](crate::FapiContext::set_sign_callback) function.
pub struct SignCallback {
    sign_fn: Box<SignCallbackFunction>,
    sign_data: Option<Vec<u8>>,
}

/// Signature of the wrapped [`SignCallback`] function
type SignCallbackFunction = dyn Fn(SignCallbackParam) -> Option<Vec<u8>> + Send;

/// Wraps the parameters to be passed to the [`SignCallback`] callback.
#[derive(Debug)]
pub struct SignCallbackParam<'a> {
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

impl SignCallback {
    /// Creates a new callback instance.
    ///
    /// The supplied `sign_fn` will be called whenever the FAPI requests a signature from the application. The purpose of this signature is to authorize a policy execution containing a *PolicySigned* element. This function receives a [`SignCallbackParam`] as parameter; it shall return `Some(value)`, if a signature value is provided by the application, or `None`, if **no** signature value is provided.
    pub fn new(sign_fn: impl Fn(SignCallbackParam) -> Option<Vec<u8>> + 'static + Send) -> Self {
        Self {
            sign_fn: Box::new(sign_fn),
            sign_data: None,
        }
    }

    /// Creates a new callback instance with additional data.
    ///
    /// The supplied `sign_fn` will be called whenever the FAPI requests a signature from the application. The purpose of this signature is to authorize a policy execution containing a *PolicySigned* element. This function receives a [`SignCallbackParam`] as parameter; it shall return `Some(value)`, if a signature value is provided by the application, or `None`, if **no** signature value is provided.
    ///
    /// The application-defined `extra_data` argument will be passed to each invocation of `sign_fn` as an additional parameter.
    pub fn with_data<T: 'static + Send>(sign_fn: impl Fn(SignCallbackParam, &T) -> Option<Vec<u8>> + 'static + Send, extra_data: T) -> Self {
        Self::new(move |callback_param| sign_fn(callback_param, &extra_data))
    }

    /// Request a signature for authorizing use of TPM objects from the application.
    pub(crate) fn invoke(
        &mut self,
        object_path: &CStr,
        description: Option<&CStr>,
        public_key: &CStr,
        key_hint: Option<&CStr>,
        hash_algo: u32,
        challenge: &[u8],
    ) -> Option<&[u8]> {
        let param = SignCallbackParam::new(object_path, description, public_key, key_hint, hash_algo, challenge);
        trace!("SignCallback::invoke({:?})", &param);
        match (self.sign_fn)(param) {
            Some(value) => {
                self.sign_data = Some(value);
                self.sign_data.as_deref()
            }
            _ => None,
        }
    }

    pub(crate) fn clear_buffer(&mut self) {
        self.sign_data.take();
    }
}

impl<'a> SignCallbackParam<'a> {
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

impl Debug for SignCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignCallback")
            .field("sign_fn", &(*self.sign_fn).type_id())
            .field("sign_data", &self.sign_data)
            .finish()
    }
}

// ==========================================================================
// BranCallback
// ==========================================================================

/// A callback function that allows the FAPI to request branch choices.
///
/// It is usually called during policy evaluation.
///
/// Registered to a FAPI context via the [`set_branch_callback()`](crate::FapiContext::set_branch_callback) function.
pub struct BranCallback {
    bran_fn: Box<BranCallbackFunction>,
}

/// Signature of the wrapped [`BranCallback`] function
type BranCallbackFunction = dyn Fn(BranCallbackParam) -> Option<usize> + Send;

/// Wraps the parameters to be passed to the [`BranCallback`] callback.
#[derive(Debug)]
pub struct BranCallbackParam<'a> {
    /// Identifies the policy (path) being executed for which a branch choice is requested.
    pub object_path: &'a str,
    /// Description as provided in the policy definition (optional).
    pub description: Option<&'a str>,
    /// A list of human readable names for the branches as from the *PolicyOR* statement.
    pub branches: Vec<&'a str>,
}

impl BranCallback {
    /// Creates a new callback instance.
    ///
    /// The supplied `bran_fn` will be called whenever a branch needs to be chosen during policy evaluation. Such choices take place when a policy contains a *PolicyOR* (with more than one branch), or a *PolicyAuthorize* (which has more than one approved policy). This function receives a [`BranCallbackParam`] as parameter; it shall return `Some(n)`, where ***n*** is the zero-based index of the chosen branch (must be less than or equal to `branches.len()-1`), or `None`, if **no** choice can be made.
    pub fn new(bran_fn: impl Fn(BranCallbackParam) -> Option<usize> + 'static + Send) -> Self {
        Self { bran_fn: Box::new(bran_fn) }
    }

    /// Creates a new callback instance with additional data.
    ///
    /// The supplied `bran_fn` will be called whenever a branch needs to be chosen during policy evaluation. Such choices take place when a policy contains a *PolicyOR* (with more than one branch), or a *PolicyAuthorize* (which has more than one approved policy). This function receives a [`BranCallbackParam`] as parameter; it shall return `Some(n)`, where ***n*** is the zero-based index of the chosen branch (must be less than or equal to `branches.len()-1`), or `None`, if **no** choice can be made.
    ///
    /// The application-defined `extra_data` argument will be passed to each invocation of `bran_fn` as an additional parameter.
    pub fn with_data<T: 'static + Send>(bran_fn: impl Fn(BranCallbackParam, &T) -> Option<usize> + 'static + Send, extra_data: T) -> Self {
        Self::new(move |callback_param| bran_fn(callback_param, &extra_data))
    }

    /// Request a signature for authorizing use of TPM objects from the application.
    pub(crate) fn invoke(&mut self, object_path: &CStr, description: Option<&CStr>, branches: &[&CStr]) -> Option<usize> {
        let param = BranCallbackParam::new(object_path, description, branches);
        trace!("BranCallback::invoke({:?})", &param);
        (self.bran_fn)(param).inspect(|index| {
            if *index >= branches.len() {
                panic!(
                    "The chosen branch index #{} is out of range! (must be in the 0..{} range)",
                    index,
                    branches.len() - 1usize
                );
            }
        })
    }
}

impl<'a> BranCallbackParam<'a> {
    fn new(object_path: &'a CStr, description: Option<&'a CStr>, branches: &'a [&CStr]) -> Self {
        Self {
            object_path: object_path.to_str().unwrap_or_default(),
            description: description.map(|str| str.to_str().unwrap_or_default()),
            branches: branches.iter().map(|str| str.to_str().unwrap_or_default()).collect(),
        }
    }
}

impl Debug for BranCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranCallback").field("bran_fn", &(*self.bran_fn).type_id()).finish()
    }
}

// ==========================================================================
// ActnCallback
// ==========================================================================

/// A callback function that allows the FAPI to notify the application.
///
/// It is usually called to announce policy actions.
///
/// Registered to a FAPI context via the [`set_policy_action_callback()`](crate::FapiContext::set_policy_action_callback) function.
pub struct ActnCallback {
    actn_fn: Box<ActnCallbackFunction>,
}

/// Signature of the wrapped [`ActnCallback`] function
type ActnCallbackFunction = dyn Fn(ActnCallbackParam) -> bool + Send;

/// Wraps the parameters to be passed to the [`ActnCallback`] callback.
#[derive(Debug)]
pub struct ActnCallbackParam<'a> {
    /// Identifies the policy (path) being executed for which an action is signaled.
    pub object_path: &'a str,
    /// The action string as specified in the PolicyAction (optional).
    pub action: Option<&'a str>,
}

impl ActnCallback {
    /// Creates a new callback instance.
    ///
    /// The supplied `actn_fn` will be called whenever a *PolicyAction* element is encountered during policy evaluation. The purpose and reaction to such an event is application dependent. This function receives a [`ActnCallbackParam`] as parameter.
    pub fn new(actn_fn: impl Fn(ActnCallbackParam) -> bool + 'static + Send) -> Self {
        Self { actn_fn: Box::new(actn_fn) }
    }

    /// Creates a new callback instance with additional data.
    ///
    /// The supplied `actn_fn` will be called whenever a *PolicyAction* element is encountered during policy evaluation. The purpose and reaction to such an event is application dependent. This function receives a [`ActnCallbackParam`] as parameter.
    ///
    /// The application-defined `extra_data` argument will be passed to each invocation of `actn_fn` as an additional parameter.
    pub fn with_data<T: 'static + Send>(actn_fn: impl Fn(ActnCallbackParam, &T) -> bool + 'static + Send, extra_data: T) -> Self {
        Self::new(move |callback_param| actn_fn(callback_param, &extra_data))
    }

    /// Request a signature for authorizing use of TPM objects from the application.
    pub(crate) fn invoke(&mut self, object_path: &CStr, action: Option<&CStr>) -> bool {
        let param = ActnCallbackParam::new(object_path, action);
        trace!("ActnCallback::invoke({:?})", &param);
        (self.actn_fn)(param)
    }
}

impl<'a> ActnCallbackParam<'a> {
    fn new(object_path: &'a CStr, action: Option<&'a CStr>) -> Self {
        Self {
            object_path: object_path.to_str().unwrap_or_default(),
            action: action.map(|str| str.to_str().unwrap_or_default()),
        }
    }
}

impl Debug for ActnCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActnCallback").field("actn_fn", &(*self.actn_fn).type_id()).finish()
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{ActnCallback, AuthCallback, BranCallback, SignCallback};
    use std::ffi::CString;

    #[test]
    fn test_callbacks() {
        let param = CString::new("my param").unwrap();

        let mut callback = AuthCallback::new(|_param| None);
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None);

        let mut callback = AuthCallback::with_data(|_param, _data| None, "my data");
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None);

        let mut callback = SignCallback::new(|_param| None);
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None, &param, None, 0, &[0u8]);

        let mut callback = SignCallback::with_data(|_param, _data| None, "my data");
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None, &param, None, 0, &[0u8]);

        let mut callback = BranCallback::new(|_param| None);
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None, &[&param]);

        let mut callback = BranCallback::with_data(|_param, _data| None, "my data");
        let _ = format!("{:?}", callback);
        callback.invoke(&param, None, &[&param]);

        let mut callback = ActnCallback::new(|_param| true);
        let _ = format!("{:?}", callback);
        callback.invoke(&param, Some(&param));

        let mut callback = ActnCallback::with_data(|_param, _data| true, "my data");
        let _ = format!("{:?}", callback);
        callback.invoke(&param, Some(&param));
    }
}
