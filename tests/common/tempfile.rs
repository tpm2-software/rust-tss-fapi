/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use rand::RngCore;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub struct TempFile {
    file_path: PathBuf,
}

impl TempFile {
    pub fn new(base_dir: &Path) -> Option<TempFile> {
        Self::with_suffix(base_dir, "tmp")
    }

    pub fn with_suffix(base_dir: &Path, suffix: &str) -> Option<TempFile> {
        assert!(!suffix.is_empty() && suffix.chars().all(|c| char::is_ascii_alphanumeric(&c)));
        let mut rng = rand::thread_rng();

        for _i in 0..99 {
            let file_path = base_dir.join(format!("temp-{:16X}.{}", rng.next_u64(), suffix));
            if File::create_new(&file_path).is_ok() {
                return Some(TempFile { file_path });
            }
        }

        None /* failed to generate unique temp file name*/
    }

    pub fn path(&self) -> &Path {
        &self.file_path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _success = fs::remove_file(&self.file_path);
    }
}
