/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use crate::{fapi_sys, ErrorCode};
use json::JsonValue;
use std::{
    borrow::Cow,
    ffi::{c_char, c_void, CStr, CString, NulError},
    ptr, slice,
};

#[cfg(unix)]
use libc::explicit_bzero;

const INVALID_ARGUMENTS: ErrorCode = ErrorCode::InternalError(crate::InternalError::InvalidArguments);

// ==========================================================================
// Helper macros
// ==========================================================================

macro_rules! fail_if_empty {
    ($str:ident) => {
        if $str.is_empty() {
            return Err(INVALID_ARGUMENTS);
        }
    };
}

macro_rules! fail_if_opt_empty {
    ($opt_str:ident) => {
        if let Some(strval) = $opt_str.as_ref() {
            fail_if_empty!(strval)
        }
    };
}

// ==========================================================================
// CStringHolder
// ==========================================================================

/// Wrapper class to encapsulate a string as `ffi:CString`.
#[derive(Debug)]
pub struct CStringHolder {
    str_data: Option<CString>,
}

impl CStringHolder {
    /// Returns a pointer to the wrapped NUL-terminated string, which is guaranteed to remain valid until the `CStringHolder` instance is dropped.
    pub fn as_ptr(&self) -> *const c_char {
        self.str_data.as_ref().map_or(ptr::null(), |str| str.as_ptr())
    }

    /* pub fn as_c_str(&self) -> Option<&CStr> {
        self.str_data.as_ref().map(CString::as_c_str)
    } */

    fn force_clear(&mut self) {
        if let Some(data) = self.str_data.take() {
            erase_memory(data.as_ptr(), data.count_bytes());
        }
    }
}

impl Drop for CStringHolder {
    fn drop(&mut self) {
        self.force_clear();
    }
}

impl TryFrom<&str> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `&str` slice.
    fn try_from(str: &str) -> Result<Self, ErrorCode> {
        fail_if_empty!(str);
        Ok(Self {
            str_data: Some(CString::new(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<String> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `String` object.
    fn try_from(str: String) -> Result<Self, ErrorCode> {
        fail_if_empty!(str);
        Ok(Self {
            str_data: Some(CString::new(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<Cow<'static, str>> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `Cow<'static, str>` value.
    fn try_from(str: Cow<'static, str>) -> Result<Self, ErrorCode> {
        fail_if_empty!(str);
        Ok(Self {
            str_data: Some(cstring_from_cow(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<&JsonValue> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `JsonValue` value.
    fn try_from(json: &JsonValue) -> Result<Self, ErrorCode> {
        fail_if_empty!(json);
        Ok(Self {
            str_data: Some(CString::new(json.to_string()).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<Option<&str>> for CStringHolder {
    type Error = ErrorCode;

    /// Create sa new `CStringHolder` from a given `Option<&str>`. The new instance will contain a `NULL` pointer, if the given `opt_str` was `None`.
    fn try_from(opt_str: Option<&str>) -> Result<Self, ErrorCode> {
        fail_if_opt_empty!(opt_str);
        Ok(Self {
            str_data: opt_str.map(|str| CString::new(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<Option<String>> for CStringHolder {
    type Error = ErrorCode;

    /// Create sa new `CStringHolder` from a given `Option<&str>`. The new instance will contain a `NULL` pointer, if the given `opt_str` was `None`.
    fn try_from(opt_str: Option<String>) -> Result<Self, ErrorCode> {
        fail_if_opt_empty!(opt_str);
        Ok(Self {
            str_data: opt_str.map(|str| CString::new(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<Option<Cow<'static, str>>> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `Option<Cow<'static, str>>`. The new instance will contain a `NULL` pointer, if the given `opt_str` was `None`.
    fn try_from(opt_str: Option<Cow<'static, str>>) -> Result<Self, ErrorCode> {
        fail_if_opt_empty!(opt_str);
        Ok(Self {
            str_data: opt_str.map(|str| cstring_from_cow(str).expect("Failed to allocate CString!")),
        })
    }
}

impl TryFrom<Option<&JsonValue>> for CStringHolder {
    type Error = ErrorCode;

    /// Creates a new `CStringHolder` from a given `Option<JsonValue>`. The new instance will contain a `NULL` pointer, if the given `opt_json` was `None`.
    fn try_from(opt_json: Option<&JsonValue>) -> Result<Self, ErrorCode> {
        fail_if_opt_empty!(opt_json);
        Ok(Self {
            str_data: opt_json.map(|json| CString::new(json.to_string()).expect("Failed to allocate CString!")),
        })
    }
}

// ==========================================================================
// MemoryHolder
// ==========================================================================

/// Wrapper class to hold a data pointer returned by the native FAPI.
///
/// Assumes that the pointed-to memory was allocated by the FAPI and therefore automatically releases the pointed-to memory, by calling `FAPI_Free()`, when the `FapiMemoryHolder` instance is dropped.
pub(crate) struct FapiMemoryHolder<T>
where
    T: Sized + Clone,
{
    data_ptr: *mut T,
    length: usize,
}

impl<T> FapiMemoryHolder<T>
where
    T: Sized + Clone,
{
    /// Creates a new `FapiMemoryHolder` from a "raw" pointer and a length. The pointer can be a `NULL` pointer, in which case the `length` is ignored.
    pub fn from_raw(data_ptr: *mut T, length: usize) -> Self {
        Self {
            data_ptr,
            length: if !data_ptr.is_null() { length } else { 0usize },
        }
    }

    /// Copies the wrapped data into a new `Vec<T>`, so that it can remain valid after this `FapiMemoryHolder` instance was dropped; returns `None` if wrapped pointer is `NULL`.
    pub fn to_vec(&self) -> Option<Vec<T>> {
        if (!self.data_ptr.is_null()) && (self.length > 0usize) {
            unsafe { Some(slice::from_raw_parts(self.data_ptr, self.length).to_vec()) }
        } else {
            None
        }
    }

    /* /// Returns a pointer to the wrapped data, which will be valid only until this `FapiMemoryHolder` instance is dropped!
    pub fn as_ptr(&self) -> *const T {
        self.data_ptr
    } */
}

impl FapiMemoryHolder<c_char> {
    /// Creates a new `FapiMemoryHolder` from a NUL-terminated C-string. The pointer can be a `NULL` pointer, in which case a zero-length string is assumed; otherwise the pointed-to data **must** be NUL-terminated!
    pub fn from_str(data_ptr: *mut c_char) -> Self {
        Self {
            data_ptr,
            length: if !data_ptr.is_null() {
                unsafe { CStr::from_ptr(data_ptr).count_bytes() }
            } else {
                0usize
            },
        }
    }

    /// Copies the wrapped data into an owned `String` object, so that it can remain valid after this `FapiMemoryHolder` instance was dropped; returns `None` if wrapped pointer is `NULL`.
    pub fn to_string(&self) -> Option<String> {
        if (!self.data_ptr.is_null()) && (self.length > 0usize) {
            let result = unsafe { CStr::from_ptr(self.data_ptr).to_str() };
            match result {
                Ok(cs) => Some(cs.to_owned()),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// Parses the wrapped data into an owned `JsonValue` object, so that it can remain valid after this `FapiMemoryHolder` instance was dropped; returns `None` if wrapped pointer is `NULL` or is not pointing to valid JSON data.
    pub fn to_json(&self) -> Option<JsonValue> {
        if (!self.data_ptr.is_null()) && (self.length > 0usize) {
            let result = unsafe { CStr::from_ptr(self.data_ptr).to_str() };
            match result {
                Ok(cs) => json::parse(cs).ok(),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}

impl<T> Drop for FapiMemoryHolder<T>
where
    T: Sized + Clone,
{
    fn drop(&mut self) {
        if !self.data_ptr.is_null() {
            erase_memory(self.data_ptr, self.length);
            unsafe {
                fapi_sys::Fapi_Free(self.data_ptr as *mut c_void);
            }
            self.data_ptr = ptr::null_mut();
        };
    }
}

// ==========================================================================
// Miscellaneous functions
// ==========================================================================

/// Create a string from a `c_char` pointer, will be `None` iff the pointer is a `NULL` pointer.
pub fn ptr_to_opt_cstr<'a>(str_ptr: *const c_char) -> Option<&'a CStr> {
    if !str_ptr.is_null() {
        unsafe { Some(CStr::from_ptr(str_ptr)) }
    } else {
        None
    }
}

/// Create a vector of strings from a "raw" array of `c_char` pointers
pub fn ptr_to_cstr_vec<'a>(str_ptr: *mut *const c_char, count: usize) -> Vec<&'a CStr> {
    unsafe {
        let list: &[*const c_char] = slice::from_raw_parts(str_ptr, count);
        list.iter().map(|ptr| CStr::from_ptr(*ptr)).collect()
    }
}

/// Get pointer to optional data, will be `NULL` if **no** data is actually available.
pub fn opt_to_ptr<T: Sized + Copy>(opt_data: Option<&[T]>) -> *const T {
    match opt_data {
        Some(data) => data.as_ptr(),
        None => ptr::null(),
    }
}

/// Get length of optional data, will be *zero* if **no** data is actually available.
pub fn opt_to_len<T: Sized + Copy>(opt_data: Option<&[T]>) -> usize {
    match opt_data {
        Some(data) => data.len(),
        None => 0usize,
    }
}

/// Get conditional pointer, which will be a `NULL` pointer unless the flags is *true*.
pub fn cond_ptr<T: Sized + Copy>(cond_ptr: &mut T, enabled: bool) -> *mut T {
    if enabled {
        cond_ptr
    } else {
        ptr::null_mut()
    }
}

/// Get conditional output pointer (i.e. pointer to pointer), which will be a `NULL` pointer unless the flags is *true*.
pub fn cond_out<T: Sized + Copy>(cond_ptr: &mut *mut T, enabled: bool) -> *mut *mut T {
    if enabled {
        cond_ptr
    } else {
        ptr::null_mut()
    }
}

// ==========================================================================
// Utilities
// ==========================================================================

fn erase_memory<T>(address: *const T, length: usize)
where
    T: Sized + Clone,
{
    #[cfg(unix)]
    unsafe {
        explicit_bzero(address as *mut c_void, length);
    }
    #[cfg(not(unix))]
    unsafe {
        ptr::write_bytes(address as *mut c_void, 0u8, length);
    }
}

fn cstring_from_cow(str: Cow<'static, str>) -> Result<CString, NulError> {
    match str {
        Cow::Borrowed(data) => CString::new(data),
        Cow::Owned(data) => CString::new(data),
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::CStringHolder;
    use json::JsonValue;
    use std::{borrow::Cow, ptr};

    #[test]
    fn test_cstring_holder() {
        check_some(CStringHolder::try_from("test").unwrap());
        check_some(CStringHolder::try_from("test".to_owned()).unwrap());
        check_some(CStringHolder::try_from(Cow::from("test")).unwrap());
        check_some(CStringHolder::try_from(Cow::from("test".to_owned())).unwrap());
        check_some(CStringHolder::try_from(&JsonValue::String("test".to_owned())).unwrap());
        check_some(CStringHolder::try_from(Some("test")).unwrap());
        check_some(CStringHolder::try_from(Some("test".to_owned())).unwrap());
        check_some(CStringHolder::try_from(Some(Cow::from("test"))).unwrap());
        check_some(CStringHolder::try_from(Some(Cow::from("test".to_owned()))).unwrap());
        check_some(CStringHolder::try_from(Some(&JsonValue::String("test".to_owned()))).unwrap());

        check_none(CStringHolder::try_from(Option::<&str>::None).unwrap());
        check_none(CStringHolder::try_from(Option::<String>::None).unwrap());
        check_none(CStringHolder::try_from(Option::<Cow<'static, str>>::None).unwrap());
        check_none(CStringHolder::try_from(Option::<&JsonValue>::None).unwrap());
    }

    fn check_some(holder: CStringHolder) {
        assert_ne!(holder.as_ptr(), ptr::null());
    }

    fn check_none(holder: CStringHolder) {
        assert_eq!(holder.as_ptr(), ptr::null());
    }
}
