//! Bounded per-vault key reuse shares the production KDF miss path without timing assertions.
#![allow(clippy::unwrap_used)]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

use super::*;

#[test]
fn exact_salt_and_each_cost_component_control_reuse_and_return_independent_wrapped_keys() {
    let vault = Vault::new("fixture passphrase");
    let mut derives = 0;
    let mut first = vault
        .key_with(&[1; 16], &[12, 8, 1], |password, salt, parameters, key| {
            assert_eq!(password, b"fixture passphrase");
            assert_eq!(salt, &[1; 16]);
            assert_eq!(parameters, &[12, 8, 1]);
            derives += 1;
            key.fill(0x11);
            Ok(())
        })
        .unwrap();
    assert_eq!(*first, [0x11; 32]);
    first.fill(0xff);
    let second = vault
        .key_with(&[1; 16], &[12, 8, 1], |_, _, _, _| {
            panic!("identical tuple invoked the KDF twice")
        })
        .unwrap();
    assert_eq!(*second, [0x11; 32]);
    assert_eq!(derives, 1);

    for (salt, parameters, expected) in [
        ([2; 16], [12, 8, 1], 0x22),
        ([1; 16], [13, 8, 1], 0x33),
        ([1; 16], [12, 9, 1], 0x44),
        ([1; 16], [12, 8, 2], 0x55),
    ] {
        let key = vault
            .key_with(
                &salt,
                &parameters,
                |_, actual_salt, actual_parameters, key| {
                    assert_eq!(actual_salt, &salt);
                    assert_eq!(actual_parameters, &parameters);
                    derives += 1;
                    key.fill(expected);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(*key, [expected; 32]);
    }
    assert_eq!(derives, 5);
    assert_eq!(vault.keys.lock().unwrap().len(), 5);
}

#[test]
fn identical_tuples_in_different_vaults_never_share_passphrases_or_cached_keys() {
    let mut derives = 0;
    for (password, expected) in [("first fixture", 0x11), ("second fixture", 0x22)] {
        let vault = Vault::new(password);
        let key = vault
            .key_with(&[1; 16], &[12, 8, 1], |actual_password, _, _, key| {
                assert_eq!(actual_password, password.as_bytes());
                derives += 1;
                key.fill(expected);
                Ok(())
            })
            .unwrap();
        assert_eq!(*key, [expected; 32]);
        assert_eq!(
            *vault
                .key_with(&[1; 16], &[12, 8, 1], |_, _, _, _| {
                    panic!("same vault did not reuse its own key")
                })
                .unwrap(),
            [expected; 32]
        );
    }
    assert_eq!(derives, 2);
}

#[test]
fn fifo_eviction_bounds_cached_keys_to_32_and_rederives_evicted_entries() {
    let vault = Vault::new("fixture");
    let mut derives = 0;
    for salt in 0u8..32 {
        let key = vault
            .key_with(&[salt; 16], &[12, 8, 1], |_, _, _, key| {
                derives += 1;
                key.fill(salt);
                Ok(())
            })
            .unwrap();
        assert_eq!(*key, [salt; 32]);
        assert!(vault.keys.lock().unwrap().len() <= 32);
    }
    assert_eq!(derives, 32);
    assert_eq!(vault.keys.lock().unwrap().len(), 32);
    assert_eq!(
        *vault
            .key_with(&[0; 16], &[12, 8, 1], |_, _, _, _| {
                panic!("oldest entry was evicted before the cache was full")
            })
            .unwrap(),
        [0; 32]
    );
    for salt in [32u8, 0] {
        let key = vault
            .key_with(&[salt; 16], &[12, 8, 1], |_, _, _, key| {
                derives += 1;
                key.fill(salt);
                Ok(())
            })
            .unwrap();
        assert_eq!(*key, [salt; 32]);
        assert_eq!(vault.keys.lock().unwrap().len(), 32);
    }
    assert_eq!(derives, 34, "a cache hit must not promote a FIFO entry");
}

#[test]
fn derivation_failures_are_not_cached_and_invalid_inputs_never_reach_the_kdf() {
    let vault = Vault::new("fixture");
    let mut derives = 0;
    let failed = vault.key_with(&[1; 16], &[12, 8, 1], |_, _, _, key| {
        derives += 1;
        key.fill(0xaa);
        Err(Error::protocol("controlled KDF failure"))
    });
    assert!(matches!(failed, Err(Error::Protocol(message)) if message == "controlled KDF failure"));
    assert!(vault.keys.lock().unwrap().is_empty());
    let key = vault
        .key_with(&[1; 16], &[12, 8, 1], |_, _, _, key| {
            derives += 1;
            key.fill(0xbb);
            Ok(())
        })
        .unwrap();
    assert_eq!(*key, [0xbb; 32]);
    assert_eq!(derives, 2);
    assert_eq!(
        *vault
            .key_with(&[1; 16], &[12, 8, 1], |_, _, _, _| {
                panic!("successful retry was not cached")
            })
            .unwrap(),
        [0xbb; 32]
    );
    for parameters in [
        vec![],
        vec![12, 8],
        vec![12, 8, 1, 0],
        vec![0, 8, 1],
        vec![9, 8, 1],
        vec![23, 8, 1],
        vec![64, 8, 1],
        vec![255, 8, 1],
        vec![12, 0, 1],
        vec![12, 33, 1],
        vec![12, 8, 0],
        vec![12, 8, 17],
        vec![22, 32, 16],
    ] {
        assert!(matches!(
            vault.key_with(&[1; 16], &parameters, |_, _, _, _| panic!(
                "invalid cost reached KDF"
            )),
            Err(Error::Corrupt(_))
        ));
    }
    for salt in [vec![], vec![1; 15], vec![1; 17]] {
        assert!(matches!(
            vault.key_with(&salt, &[12, 8, 1], |_, _, _, _| panic!("invalid salt reached KDF")),
            Err(Error::Corrupt(message)) if message == "Encrypted salt has invalid width"
        ));
    }
    assert_eq!(vault.keys.lock().unwrap().len(), 1);
}

#[test]
fn simultaneous_identical_requests_share_one_held_kdf_computation() {
    let vault = Vault::new("fixture");
    let derives = AtomicUsize::new(0);
    let (ready, readiness) = mpsc::sync_channel(2);
    let (entered, entering) = mpsc::sync_channel(2);
    let (start_a, started_a) = mpsc::sync_channel(1);
    let (start_b, started_b) = mpsc::sync_channel(1);
    let (release_a, released_a) = mpsc::sync_channel(1);
    let (release_b, released_b) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for (started, released) in [(started_a, released_a), (started_b, released_b)] {
            let vault = &vault;
            let derives = &derives;
            let ready = ready.clone();
            let entered = entered.clone();
            threads.push(scope.spawn(move || {
                ready.send(()).unwrap();
                started.recv_timeout(Duration::from_secs(2)).unwrap();
                vault.key_with(&[1; 16], &[12, 8, 1], |_, _, _, key| {
                    derives.fetch_add(1, Ordering::SeqCst);
                    entered.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(2)).unwrap();
                    key.fill(0x5a);
                    Ok(())
                })
            }));
        }
        for _ in 0..2 {
            readiness.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        start_a.send(()).unwrap();
        start_b.send(()).unwrap();
        entering.recv_timeout(Duration::from_secs(2)).unwrap();
        let held = matches!(
            vault.keys.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        );
        // A cache-hit worker may drop its unused receiver as soon as the deriving worker finishes.
        let released = [release_a.send(()).is_ok(), release_b.send(()).is_ok()];
        assert!(released.into_iter().any(|sent| sent));
        assert!(
            held,
            "cache lock was not held through the actual KDF boundary"
        );
        for thread in threads {
            assert_eq!(*thread.join().unwrap().unwrap(), [0x5a; 32]);
        }
    });
    assert_eq!(derives.load(Ordering::SeqCst), 1);
    assert_eq!(vault.keys.lock().unwrap().len(), 1);
}

#[test]
fn a_poisoned_cache_refuses_even_a_previously_cached_tuple_without_insecure_recovery() {
    let vault = Vault::new("fixture");
    vault
        .key_with(&[1; 16], &[12, 8, 1], |_, _, _, key| {
            key.fill(0x5a);
            Ok(())
        })
        .unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = vault.keys.lock().unwrap();
        panic!("controlled cache interruption");
    }));
    assert!(panic.is_err());
    assert!(matches!(
        vault.key_with(&[1; 16], &[12, 8, 1], |_, _, _, _| panic!("poisoned cache reached KDF")),
        Err(Error::Protocol(message)) if message == "Shared state was interrupted; refusing to continue"
    ));
}
