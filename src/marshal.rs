/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use std::{borrow::Cow, iter::repeat, mem::size_of};

const U64_SIZE: usize = size_of::<u64>();

pub(crate) fn u64_from_be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(<[u8; U64_SIZE]>::try_from(resize_be(bytes, U64_SIZE).as_ref()).unwrap())
}

pub(crate) fn resize_be(bytes: &[u8], new_size: usize) -> Cow<'_, [u8]> {
    if bytes.len() >= new_size {
        Cow::Borrowed(&bytes[bytes.len() - new_size..])
    } else {
        Cow::Owned(repeat(0u8).take(new_size - bytes.len()).chain(bytes.iter().copied()).collect::<Vec<u8>>())
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::{resize_be, u64_from_be};

    #[test]
    fn test_u64_from_be() {
        assert_eq!(
            u64_from_be(&[0x11_u8, 0x22_u8, 0x33_u8, 0x44_u8, 0x55_u8, 0x66_u8, 0x77_u8, 0x88_u8,]),
            0x1122334455667788_u64
        );
        assert_eq!(
            u64_from_be(&[0x88_u8, 0x77_u8, 0x66_u8, 0x55_u8, 0x44_u8, 0x33_u8, 0x22_u8, 0x11_u8,]),
            0x8877665544332211_u64
        );
    }

    #[test]
    fn test_resize_be() {
        let value = [0x11_u8, 0x22_u8, 0x33_u8, 0x44_u8];
        for length in 1usize..=6usize {
            match length {
                1usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x44_u8]),
                2usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x33_u8, 0x44_u8]),
                3usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x22_u8, 0x33_u8, 0x44_u8]),
                4usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x11_u8, 0x22_u8, 0x33_u8, 0x44_u8]),
                5usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x00_u8, 0x11_u8, 0x22_u8, 0x33_u8, 0x44_u8]),
                6usize => assert_eq!(resize_be(&value, length).as_ref(), &[0x00_u8, 0x00_u8, 0x11_u8, 0x22_u8, 0x33_u8, 0x44_u8]),
                _ => unreachable!(),
            }
        }
    }
}
