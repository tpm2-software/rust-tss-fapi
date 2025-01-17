/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

// ==========================================================================
// LockGuard
// ==========================================================================

pub enum LockGuard<'a, T> {
    Exclusive(RwLockWriteGuard<'a, T>),
    Shared(RwLockReadGuard<'a, T>),
}

impl<'a, T> LockGuard<'a, T> {
    pub fn acquire(rw_lock: &'a RwLock<T>, exclusive: bool) -> Self {
        if exclusive {
            Self::Exclusive(rw_lock.write().expect("Failed to acquire exclusive lock!"))
        } else {
            Self::Shared(rw_lock.read().expect("Failed to acquire shared lock!"))
        }
    }

    #[allow(dead_code)]
    pub fn is_exclusive(&self) -> bool {
        match self {
            Self::Exclusive(_guard) => true,
            Self::Shared(_guard) => false,
        }
    }
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::LockGuard;
    use std::sync::RwLock;

    static MY_MUTEX: RwLock<()> = RwLock::new(());

    #[test]
    fn test_shared() {
        let guard = LockGuard::acquire(&MY_MUTEX, false);
        assert!(!guard.is_exclusive());
        assert!(matches!(guard, LockGuard::Shared(_read_guard)));
    }

    #[test]
    fn test_exclusive() {
        let guard = LockGuard::acquire(&MY_MUTEX, true);
        assert!(guard.is_exclusive());
        assert!(matches!(guard, LockGuard::Exclusive(_write_guard)));
    }
}
