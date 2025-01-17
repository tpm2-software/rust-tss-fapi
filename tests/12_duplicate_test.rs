/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{param::PASSWORD, setup::TestConfiguration};
use function_name::named;
use json::{Error as JsonError, JsonValue};
use log::debug;
use serial_test::serial;
use tss2_fapi_rs::{FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const PARENT_KEY_FLAGS: &[KeyFlags] = &[KeyFlags::Restricted, KeyFlags::Decrypt, KeyFlags::NoDA];
const EXPORT_KEY_FLAGS: &[KeyFlags] = &[KeyFlags::Exportable, KeyFlags::Decrypt, KeyFlags::NoDA];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `export_key()` and `import()` functions to duplicate an extsing key, by using a `POLICYDUPLICATIONSELECT` policy
#[test]
#[serial]
#[named]
fn test_duplicate_key() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let offset = 2usize.checked_mul(i).unwrap();

        let crypt_key1 = &format!("HS/SRK/myCryptKey{}", offset);
        let crypt_key2 = &format!("HS/SRK/myCryptKey{}", offset.checked_add(1usize).unwrap());
        let new_parent = &format!("ext/myNewParentKey{}", offset);
        let child_key1 = &format!("{}/myChildKey{}", crypt_key1, offset);
        let child_key2 = &format!("myImportedKey{}", offset);
        let dup_policy = &format!("/policy/pol_duplicate{}", offset);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #1: Create the parent keys
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create parent key #1, if not already created
        match context.create_key(crypt_key1, Some(PARENT_KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Create parent key #2, if not already created
        match context.create_key(crypt_key2, Some(PARENT_KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #2: Get public key of new parent
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Export public key
        let json_public_key = match context.export_key(crypt_key2, None) {
            Ok(exported) => exported,
            Err(error) => panic!("Key export (public) has failed: {:?}", error),
        };

        // Verify
        debug!("Exported public key: {:?}", json_public_key);
        assert!(!json_public_key.is_empty());

        // Import public key
        match context.import(new_parent, &json_public_key) {
            Ok(_) => debug!("Key imported."),
            Err(error) => panic!("Failed to import the key: {:?}", error),
        };

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #3: Create the exportable key
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Build the duplication policy
        let policy_json = create_duplication_policy(new_parent).expect("Failed to create policy!");

        // Import policy
        match context.import(dup_policy, &policy_json) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create the exportable key, if not already created
        match context.create_key(child_key1, Some(EXPORT_KEY_FLAGS), Some(dup_policy), None) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #4: Export the private key (wrapped)
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Export private key
        let json_wrapped_key = match context.export_key(child_key1, Some(new_parent)) {
            Ok(exported) => exported,
            Err(error) => panic!("Key export (private) has failed: {:?}", error),
        };

        // Verify
        debug!("Exported wrapped key: {:?}", json_wrapped_key);
        assert!(!json_wrapped_key.is_empty());

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #5: Import the wrapped key
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Import wrapped key
        match context.import(child_key2, &json_wrapped_key) {
            Ok(_) => debug!("Key imported."),
            Err(error) => panic!("Failed to import the key: {:?}", error),
        };

        // Enumerate keys
        match context.list(crypt_key2) {
            Ok(mut list) => {
                let duplicated_key = format!("{}/{}", &crypt_key2, child_key2).to_ascii_lowercase();
                assert!(list.drain(..).any(|entry| entry.to_ascii_lowercase().ends_with(&duplicated_key[..])));
            }
            Err(error) => panic!("Failed to enumerate the keys: {:?}", error),
        };
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

const POLICY_TEMPLATE: &str = "{\"description\":\"Description pol_duplicate\",\"policy\":[{\"type\":\"POLICYDUPLICATIONSELECT\",\"newParentPath\":\"\"}]}";

/// Create new POLICYDUPLICATIONSELECT policy
fn create_duplication_policy(new_parent_path: &str) -> Result<JsonValue, JsonError> {
    let mut policy_json = json::parse(POLICY_TEMPLATE)?;
    policy_json["policy"][0usize]["newParentPath"] = JsonValue::String(new_parent_path.to_owned());
    Ok(policy_json)
}
