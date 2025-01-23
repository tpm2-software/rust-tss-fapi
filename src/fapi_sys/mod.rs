/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

#![allow(clippy::all)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

pub mod constants;

include!(concat!(env!("OUT_DIR"), "/tss2_fapi_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/tss2_fapi_versinfo.rs"));
