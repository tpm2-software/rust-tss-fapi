/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use log::{debug, trace};
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use serial_test::serial;
use tss2_fapi_rs::{FapiContext, NvFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const NV_ORDINARY_FLAGS: &[NvFlags] = &[NvFlags::NoDA];
const NV_COUNTER_FLAGS: &[NvFlags] = &[NvFlags::Counter, NvFlags::NoDA];
const NV_BITFIELD_FLAGS: &[NvFlags] = &[NvFlags::BitField, NvFlags::NoDA];
const NV_PCR_FLAGS: &[NvFlags] = &[NvFlags::PCR, NvFlags::NoDA];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `nv_write()` function on some newly created NV index
#[test]
#[serial]
#[named]
fn test_nv_write() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let nv_path = &format!("nv/Owner/myNv{}", i);
        let mut data = [0u8; 128usize];

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create NV index, if not already created
        match context.create_nv(nv_path, Some(NV_ORDINARY_FLAGS), data.len(), None, None) {
            Ok(_) => debug!("NV index created."),
            Err(error) => panic!("NV index creation has failed: {:?}", error),
        }

        // Generate random data
        thread_rng().fill_bytes(&mut data[..]);

        // Write data to NV index
        match context.nv_write(nv_path, &data[..]) {
            Ok(_) => debug!("Data written."),
            Err(error) => panic!("Writing data to NV index has failed: {:?}", error),
        }

        // Generate random number
        let number = thread_rng().next_u64();

        // Write number to NV index
        match context.nv_write_u64(nv_path, number) {
            Ok(_) => debug!("Number written."),
            Err(error) => panic!("Writing data to NV index has failed: {:?}", error),
        }
    });
}

/// Test the `nv_read()` function to read back data that was written to a NV index via the `nv_write()` function
#[test]
#[serial]
#[named]
fn test_nv_read() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let nv_path = &format!("nv/Owner/myNv{}", i);
        let mut data = [0u8; 128usize];

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create NV index, if not already created
        match context.create_nv(nv_path, Some(NV_ORDINARY_FLAGS), data.len(), None, None) {
            Ok(_) => debug!("NV index created."),
            Err(error) => panic!("NV index creation has failed: {:?}", error),
        }

        // Generate random data
        thread_rng().fill_bytes(&mut data[..]);

        // Write data to NV index
        match context.nv_write(nv_path, &data[..]) {
            Ok(_) => debug!("Data written."),
            Err(error) => panic!("Writing data to NV index has failed: {:?}", error),
        }

        // Read data from NV index
        let recovered_data = match context.nv_read(nv_path, false) {
            Ok(data) => data,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Validate the result
        assert!(recovered_data.0[..].eq(&data[..]));
        assert!(recovered_data.1.is_none());
    });
}

/// Test the `nv_increment()` function to increment (multiple times) a NV index that was created in "counter" mode, verify updated value via the `nv_read_u64()` function
#[test]
#[serial]
#[named]
fn test_nv_counter() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let nv_path = &format!("nv/Owner/myNvCtr{}", i);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create NV index, if not already created
        match context.create_nv(nv_path, Some(NV_COUNTER_FLAGS), 0usize, None, None) {
            Ok(_) => debug!("NV index created."),
            Err(error) => panic!("NV index creation has failed: {:?}", error),
        }

        // Increment the counter
        match context.nv_increment(nv_path) {
            Ok(_) => debug!("Incremented."),
            Err(error) => panic!("Incrementing the NV index has failed: {:?}", error),
        };

        // Read data from NV index
        let counter_1 = match context.nv_read_u64(nv_path) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Increment the counter
        match context.nv_increment(nv_path) {
            Ok(_) => debug!("Incremented."),
            Err(error) => panic!("Incrementing the NV index has failed: {:?}", error),
        };

        // Read data from NV index
        let counter_2 = match context.nv_read_u64(nv_path) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Validate the result
        debug!("Counter value #1: 0x{:016X}", counter_1);
        debug!("Counter value #2: 0x{:016X}", counter_2);

        // Verify
        assert_eq!(counter_1 + 1u64, counter_2);
    });
}

/// Test the `nv_set_bits()` function to set some bits in a NV index that was created in "BitField" mode, verify updated value via the `nv_read_u64()` function
#[test]
#[serial]
#[named]
fn test_nv_bitset() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let nv_path = &format!("nv/Owner/myNvBits{}", i);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create NV index, if not already created
        match context.create_nv(nv_path, Some(NV_BITFIELD_FLAGS), 0usize, None, None) {
            Ok(_) => debug!("NV index created."),
            Err(error) => panic!("NV index creation has failed: {:?}", error),
        }

        // Initialize bits in NV index
        match context.nv_set_bits(nv_path, 0u64) {
            Ok(_) => debug!("Bits set."),
            Err(error) => panic!("Setting the NV index bits has failed: {:?}", error),
        };

        // Read data from NV index
        let bits_0 = match context.nv_read_u64(nv_path) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Set bits in NV index
        match context.nv_set_bits(nv_path, 0x5555555555555555u64) {
            Ok(_) => debug!("Bits set."),
            Err(error) => panic!("Setting the NV index bits has failed: {:?}", error),
        };

        // Read data from NV index
        let bits_1 = match context.nv_read_u64(nv_path) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Set bits in NV index
        match context.nv_set_bits(nv_path, 0xAAAAAAAAAAAAAAAAu64) {
            Ok(_) => debug!("Bits set."),
            Err(error) => panic!("Setting the NV index bits has failed: {:?}", error),
        };

        // Read data from NV index
        let bits_2 = match context.nv_read_u64(nv_path) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Validate the result
        debug!("Counter value #0: 0x{:016X}", bits_0);
        debug!("Counter value #1: 0x{:016X}", bits_1);
        debug!("Counter value #2: 0x{:016X}", bits_2);

        // Verify
        assert_eq!(bits_0 ^ bits_1, 0x5555555555555555u64);
        assert_eq!(bits_1 ^ bits_2, 0xAAAAAAAAAAAAAAAAu64);
    });
}

/// Test the `nv_extend()` function to update a NV index that was created in "PCR" mode, verify updated value via the `nv_read()` function
#[test]
#[serial]
#[named]
fn test_nv_pcr() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let nv_path = &format!("nv/Owner/myNvPcr{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create NV index, if not already created
        match context.create_nv(nv_path, Some(NV_PCR_FLAGS), 0usize, None, None) {
            Ok(_) => debug!("NV index created."),
            Err(error) => panic!("NV index creation has failed: {:?}", error),
        }

        // Prepare log data
        let log_data = [
            json::parse("{ \"test\": \"1st value\" }").unwrap(),
            json::parse("{ \"test\": \"2nd value\" }").unwrap(),
        ];

        // Extend PCR at NV index
        match context.nv_extend(nv_path, &generate_bytes::<128usize>(&mut rng)[..], Some(&log_data[0])) {
            Ok(_) => debug!("Extended."),
            Err(error) => panic!("Incrementing NV index has failed: {:?}", error),
        };

        // Read data from NV index
        let pcr_value_1 = match context.nv_read(nv_path, true) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Print PCR data #1
        assert!(pcr_value_1.0.len() >= 20usize);
        debug!("PCR value #1: 0x{}", hex::encode(&pcr_value_1.0[..]));
        if let Some(log_data) = pcr_value_1.1 {
            trace!("PCR log data: {:?}", log_data);
            assert!(log_data.is_array());
        }

        // Extend PCR at NV index
        match context.nv_extend(nv_path, &generate_bytes::<128usize>(&mut rng)[..], Some(&log_data[1])) {
            Ok(_) => debug!("Extended."),
            Err(error) => panic!("Incrementing NV index has failed: {:?}", error),
        };

        // Read data from NV index
        let pcr_value_2 = match context.nv_read(nv_path, true) {
            Ok(value) => value,
            Err(error) => panic!("Reading data from NV index has failed: {:?}", error),
        };

        // Print PCR data #2
        assert!(pcr_value_2.0.len() >= 20usize);
        debug!("PCR value #2: 0x{}", hex::encode(&pcr_value_2.0[..]));
        if let Some(log_data) = pcr_value_2.1 {
            trace!("PCR log data: {:?}", log_data);
            assert!(log_data.is_array());
        }

        // Verify
        assert_eq!(pcr_value_1.0.len(), pcr_value_2.0.len());
        assert!(pcr_value_1.0[..].ne(&pcr_value_2.0[..]));
    });
}
