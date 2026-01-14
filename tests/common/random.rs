/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use rand::{Rng, RngCore};
use std::{array, fmt::Debug};

/// Create seed value from index
pub fn create_seed<const N: usize, T: TryInto<u64> + Debug>(value: T) -> [u8; N]
where
    <T as TryInto<u64>>::Error: std::fmt::Debug,
{
    let mut seed_data = [0u8; N];
    let value_bytes = value.try_into().unwrap().to_be_bytes();
    if N > value_bytes.len() {
        seed_data[N - value_bytes.len()..].copy_from_slice(&value_bytes[..]);
    } else {
        seed_data[..].copy_from_slice(&value_bytes[value_bytes.len() - N..]);
    }
    seed_data
}

/// Generate pseudo-random bytes
pub fn generate_bytes<const N: usize>(rand_gen: &mut impl RngCore) -> [u8; N] {
    let mut rand_data = [0u8; N];
    rand_gen.fill_bytes(&mut rand_data);
    rand_data
}

/// Generate pseudo-random bytes
pub fn generate_string<const N: usize>(rand_gen: &mut impl RngCore) -> String {
    const ASCII_PRINTABLE: [char; 94] = [
        '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>',
        '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',
        ']', '^', ' ', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '{', '|', '}', '~',
    ];
    let rand_str: [char; N] = array::from_fn(|_| ASCII_PRINTABLE[rand_gen.random_range(0..ASCII_PRINTABLE.len())]);
    String::from_iter(rand_str)
}
