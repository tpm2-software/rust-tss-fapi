/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

use log::info;
use std::{sync::OnceLock, usize};

/* Defaults */
const LOOPS_DEFAULT_VALUE: usize = 3;

/* One-time initialization */
static TEST_LOOPS: OnceLock<usize> = OnceLock::new();

/// Repeat the given function (e.g. test) `n` times. Should be invoked by using the `repeat_test!()` macro!
pub fn _repeat_test<F: Fn(usize)>(name: &str, test_fn: F) {
    let loops = *TEST_LOOPS.get_or_init(|| {
        option_env!("FAPI_RS_TEST_LOOP")
            .and_then(|str| str.parse::<usize>().ok())
            .unwrap_or(LOOPS_DEFAULT_VALUE)
    });
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

/// Skip test conditionally on profile name.
#[macro_export]
macro_rules! skip_test_ifeq {
    ($conf:ident, $name:literal) => {
        if $conf.prof_name().get(..$name.len()).map_or(false, |name| name.eq_ignore_ascii_case($name)) {
            warn!("Skipping this test for \"{}\" profile!", $name);
            return; /* skip! */
        }
    };
}

/// Set up the auth callback and then perform the initial provisioning.
///
/// This function ignores a possible "AlreadyProvisioned" error, because that kind of error is expected for all but the very first test!
#[macro_export]
macro_rules! tpm_initialize {
    ($context:ident, $password:ident, $auth_cb:ident) => {
        if let Err(error) = $context.set_auth_callback(tss2_fapi_rs::AuthCallback::new($auth_cb)) {
            panic!("Setting up the callback has failed: {:?}", error)
        }

        match $context.provision(None, Some($password), None) {
            Ok(_) => log::debug!("Provisioned."),
            Err(tss2_fapi_rs::ErrorCode::FapiError(tss2_fapi_rs::BaseErrorCode::AlreadyProvisioned)) => log::debug!("TPM already provisioned."),
            Err(error) => panic!("Provisioning has failed: {:?}", error),
        }
    };
}

/// The "auth" callback implementation used for testing.
#[macro_export]
macro_rules! mk_auth_callback {
    ($fn_name:ident, $password:expr) => {
        fn $fn_name(param: tss2_fapi_rs::AuthCallbackParam) -> Option<std::borrow::Cow<'static, str>> {
            log::debug!("(AUTH_CB) Auth value for path {:?} has been requested!", param.object_path);
            log::trace!("(AUTH_CB) Parameters: {:?}", param);

            let object_path = param
                .object_path
                .find('/')
                .map(|pos| &param.object_path[pos + 1usize..])
                .unwrap_or(param.object_path);
            if !object_path.eq("HS") && !object_path.starts_with("HS/SRK/my") {
                log::warn!("(AUTH_CB) The requested object path {:?} is not recognized!", object_path);
                return None;
            }

            Some(std::borrow::Cow::Borrowed($password))
        }
    };
}

/// Perform final clean-up of all objects created during test run(s).
#[macro_export]
macro_rules! mk_tpm_finalizer {
    ($fn_name:ident, $auth_cb:ident) => {
        fn $fn_name() {
            log::debug!("Cleaning up the TPM now!");
            if FapiContext::new()
                .and_then(|mut fpai_ctx| {
                    fpai_ctx
                        .set_auth_callback(tss2_fapi_rs::AuthCallback::new($auth_cb))
                        .and_then(|_| fpai_ctx.delete("/"))
                })
                .is_err()
            {
                log::warn!("Failed to clean-up test objects, take care!");
            }
        }
    };
}
