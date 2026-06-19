/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use super::callback::MyCallbacks;
use log::info;
use std::sync::OnceLock;

/* Defaults */
const LOOPS_DEFAULT_VALUE: usize = 3;

/* One-time initialization */
static TEST_LOOPS: OnceLock<usize> = OnceLock::new();

/// Repeat the given function (e.g. test) `n` times. Should be invoked by using the `repeat_test!()` macro!
pub fn _repeat_test<F: Fn(usize)>(name: &str, test_fn: F) {
    let loops = *TEST_LOOPS.get_or_init(|| option_env!("FAPI_RS_TEST_LOOP").and_then(|str| str.parse::<usize>().ok()).unwrap_or(LOOPS_DEFAULT_VALUE));
    for i in 0..loops {
        info!("\u{25B6} {}, execution {} of {} \u{25C0}", name, i + 1, loops);
        test_fn(i);
    }
}

/// Repeat the given function (e.g. test) `n` times.
#[macro_export]
macro_rules! repeat_test {
    ($func:expr) => {
        $crate::common::utils::_repeat_test(function_name!(), $func)
    };
}

/// Skip test conditionally, based on profile name.
#[macro_export]
macro_rules! skip_if_profile_eq {
    ($conf:ident, $name:literal) => {
        if $conf.prof_name().get(..$name.len()).map_or(false, |name| name.eq_ignore_ascii_case($name)) {
            warn!("Skipping this test for the \"{}\" profile!", $name);
            return; /* skip test! */
        }
    };
}

/// Check `libtss2-fapi` library version at runtime.
#[macro_export]
macro_rules! libtss2_version_lt {
    ($major:literal, $minor:literal) => {{
        let _version = tss2_fapi_rs::get_version();
        (_version.library.major < $major) || ((_version.library.major == $major) && (_version.library.minor < $minor))
    }};
}

/// Set up the auth callback and then perform the initial provisioning.
///
/// This function ignores a possible "AlreadyProvisioned" error, because that kind of error is expected for all but the very first test!
#[macro_export]
macro_rules! tpm_initialize {
    ($context:ident, $password:ident, $callbacks:expr) => {
        if let Err(error) = $context.set_callbacks($callbacks) {
            panic!("Setting up the callback has failed: {:?}", error)
        }

        match $context.provision(None, Some($password), None) {
            Ok(_) => log::debug!("Provisioned."),
            Err(tss2_fapi_rs::ErrorCode::FapiError(tss2_fapi_rs::BaseErrorCode::AlreadyProvisioned)) => log::debug!("TPM already provisioned."),
            Err(error) => panic!("Provisioning has failed: {:?}", error),
        }
    };
}

/// TPM finalizer
pub fn my_tpm_finalizer(password: &'static str) {
    log::debug!("Cleaning up the TPM now!");
    let callbacks = MyCallbacks::new(password, None);
    if let Err(error) = tss2_fapi_rs::FapiContext::new().and_then(|mut fpai_ctx| fpai_ctx.set_callbacks(callbacks).and_then(|_| fpai_ctx.delete("/"))) {
        if !matches!(error, tss2_fapi_rs::ErrorCode::FapiError(tss2_fapi_rs::BaseErrorCode::NotProvisioned)) {
            log::error!("Failed to clean up TPM, take care! [{:?}]", error);
        }
    }
}
