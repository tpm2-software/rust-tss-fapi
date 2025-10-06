/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

// ==========================================================================
// LockGuard
// ==========================================================================

#[cfg(feature = "locking")]
mod lock_impl {
    use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

    pub enum LockGuard<'a, T> {
        Exclusive(RwLockWriteGuard<'a, T>),
        Shared(RwLockReadGuard<'a, T>),
    }

    impl<'a, T> LockGuard<'a, T> {
        pub fn acquire(rw_lock: &'a RwLock<T>, exclusive: bool) -> Self {
            if cfg!(feature = "full_locking") || exclusive {
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
}

#[cfg(not(feature = "locking"))]
mod lock_impl {
    use std::sync::RwLock;

    pub enum LockGuard {
        None,
    }

    impl LockGuard {
        pub fn acquire<T>(_rw_lock: &RwLock<T>, _exclusive: bool) -> Self {
            LockGuard::None
        }

        #[allow(dead_code)]
        pub fn is_exclusive(&self) -> bool {
            panic!("Error: Locking feature is not enabled!")
        }
    }
}

pub use lock_impl::LockGuard;

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
#[cfg(feature = "locking")]
mod tests {
    use super::LockGuard;
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Barrier, RwLock,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    #[test]
    fn test_lock() {
        static TEST_RWLOCK: RwLock<()> = RwLock::new(());
        {
            let guard = LockGuard::acquire(&TEST_RWLOCK, false);
            assert!(!guard.is_exclusive());
            assert!(matches!(guard, LockGuard::Shared(_read_guard)));
        }
        {
            let guard = LockGuard::acquire(&TEST_RWLOCK, true);
            assert!(guard.is_exclusive());
            assert!(matches!(guard, LockGuard::Exclusive(_write_guard)));
        }
    }

    #[test]
    fn test_threads() {
        static TEST_RWLOCK: RwLock<()> = RwLock::new(());
        const THREAD_COUNT: usize = 32usize;
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let mut thread_list = VecDeque::with_capacity(THREAD_COUNT);
        let counter = Arc::new(AtomicUsize::new(0usize));
        for _tid in 0..THREAD_COUNT {
            let thread_barrier = Arc::clone(&barrier);
            let thread_counter = Arc::clone(&counter);
            thread_list.push_back(thread::spawn(move || {
                let is_leader = thread_barrier.wait().is_leader();
                for _iteration in 0..100000 {
                    let guard = LockGuard::acquire(&TEST_RWLOCK, is_leader);
                    let value = thread_counter.fetch_add(1usize, Ordering::Relaxed);
                    if guard.is_exclusive() {
                        assert_eq!(value, 0usize, "Invalid counter value!");
                    }
                    thread::yield_now();
                    thread_counter.fetch_sub(1usize, Ordering::Relaxed);
                }
            }));
        }
        for thread in thread_list.drain(..) {
            thread.join().unwrap();
        }
    }
}
