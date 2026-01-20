/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use super::crypto::{PrivateKey, create_signature};
use log::{debug, trace, warn};
use std::{borrow::Cow, sync::RwLock};
use tss2_fapi_rs::{AuthCbParam, BranchCbParam, PolicyActionCbParam, SignCbParam};

// ==========================================================================
// Callbacks
// ==========================================================================

#[derive(Debug)]
pub struct MyCallbacks {
    password: &'static str,
    private_key: Option<PrivateKey>,
    branches: RwLock<Vec<String>>,
    actions: RwLock<Vec<String>>,
}

impl MyCallbacks {
    pub fn new(password: &'static str, private_key: Option<PrivateKey>) -> Self {
        Self { password, private_key, branches: RwLock::new(Vec::new()), actions: RwLock::new(Vec::new()) }
    }

    pub fn get_branches(&self) -> Vec<String> {
        self.branches.read().unwrap().clone()
    }

    pub fn get_actions(&self) -> Vec<String> {
        self.actions.read().unwrap().clone()
    }
}

impl tss2_fapi_rs::FapiCallbacks for MyCallbacks {
    /// The "auth" callback implementation used for testing
    fn auth_cb(&self, param: AuthCbParam) -> Option<Cow<'static, str>> {
        log::debug!("(AUTH_CB) Auth value for path {:?} has been requested!", param.object_path);
        log::trace!("(AUTH_CB) Parameters: {:?}", param);

        let object_path = param.object_path.find('/').map(|pos| &param.object_path[pos + 1usize..]).unwrap_or(param.object_path);
        if !object_path.eq("HS") && !object_path.starts_with("HS/SRK/my") {
            log::warn!("(AUTH_CB) The requested object path {:?} is not recognized!", object_path);
            return None;
        }

        Some(Cow::Borrowed(self.password))
    }

    /// The "sign" callback implementation used for testing
    fn sign_cb(&self, param: SignCbParam) -> Option<Vec<u8>> {
        debug!("(SIGN_CB) Signature for {:?} has been requested!", param.object_path);
        trace!("(SIGN_CB) Parameters: {:?}", param);

        if let Some(private_key) = self.private_key.as_ref() {
            let signature_value = create_signature(private_key, &param.hash_algo, param.challenge);
            if let Some(signature_bytes) = signature_value.as_ref() {
                debug!("(SIGN_CB) Computed signature value: {}", hex::encode(&signature_bytes[..]));
            } else {
                warn!("(SIGN_CB) Failed to generate the signature!");
            }
            signature_value
        } else {
            panic!("Private key not loaded!");
        }
    }

    /// The "branch" callback implementation used for testing
    fn branch_cb(&self, param: BranchCbParam) -> Option<usize> {
        debug!("(BRAN_CB) Branch for {:?} has been requested!", param.object_path);
        trace!("(BRAN_CB) Parameters: {:?}", param);

        let mut branches = self.branches.write().unwrap();
        branches.clear();
        for name in param.branches.iter().enumerate() {
            branches.push(format!("#{},{}", name.0, name.1.trim()));
        }

        Some(0usize)
    }

    /// The "action" callback implementation used for testing
    fn policy_action_cb(&self, param: PolicyActionCbParam) -> bool {
        debug!("(ACTN_CB) Action for {:?} has been requested!", param.object_path);
        trace!("(ACTN_CB) Parameters: {:?}", param);

        let mut actions = self.actions.write().unwrap();
        if let Some(action) = param.action {
            actions.push(action.trim().to_owned());
        }

        param.action.is_some()
    }
}
