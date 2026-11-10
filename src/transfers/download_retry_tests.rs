//! Count injected send-boundary refusals through the existing production chunk retry loop.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    protocol::{metadata::DownloadSource, transport::Transport},
    storage::proxies::Routing,
};

#[test]
fn a_policy_send_boundary_refusal_is_returned_after_one_call_without_mutating_saved_coverage() {
    for transient_first in [false, true] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-retry");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let destination = scratch.path().join("unused");
        let mut file = File::create(&destination).unwrap();
        file.write_all(&[0x5a; 4096]).unwrap();
        file.sync_all().unwrap();
        let control = Control::new();
        let transport = Transport::new(
            Routing {
                explicit: None,
                pool: None,
                force: true,
            },
            Duration::from_secs(1),
            "retry-fixture".into(),
            control.clone(),
        )
        .unwrap();
        let api = Api::new(transport, control.clone()).unwrap();
        let info = FileInfo {
            name: "unused".into(),
            size: 4096,
            raw_key: Zeroizing::new(vec![0; 32]),
            url: "https://cdn.invalid/f".into(),
            handle: "fixture".into(),
            public_id: "fixture".into(),
            source: DownloadSource::Public,
        };
        let mut state = TransferState::new("download", "x", &destination, 4096, &[0; 32]).unwrap();
        state.staging_name = Some("unused".into());
        state.staging_identity = Some(file_identity(&file).unwrap());
        let state_path = scratch.path().join("private/state.json");
        let states = States::new(&state_path);
        states.save(&state).unwrap();
        let before = std::fs::read(&state_path).unwrap();
        let shared = Mutex::new(Shared {
            api,
            info,
            generation: 0,
            file,
            state,
            completed: 0,
            error: None,
        });
        let progress = Progress::new(false);
        let item = progress.add("unused", 4096).unwrap();
        let options = DownloadOptions {
            workers: 1,
            verify: false,
            overwrite: false,
            resume: true,
            keep_state: true,
            quota_wait: 0,
            quota_attempts: 1,
        };
        let mut attempts = 0;
        let result = fetch_chunk_with_send(
            chunks::Chunk {
                index: 0,
                offset: 0,
                size: 1024,
            },
            &shared,
            &states,
            &options,
            &RateLimiter::new(0.0).unwrap(),
            &progress,
            item,
            &control,
            |_, url, headers| {
                attempts += 1;
                assert_eq!(url.as_str(), "https://cdn.invalid/f");
                assert_eq!(headers[RANGE], "bytes=0-1023");
                if transient_first && attempts == 1 {
                    Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "reset",
                    )))
                } else {
                    Err(Error::protocol("pool exhausted"))
                }
            },
        );
        assert!(matches!(result, Err(Error::Protocol(message)) if message == "pool exhausted"));
        assert_eq!(
            attempts,
            if transient_first { 2 } else { 1 },
            "policy send-boundary refusal was retried or a transient reset was made final"
        );
        let shared = shared.lock().unwrap();
        assert!(shared.state.completed.is_empty());
        assert_eq!(shared.completed, 0);
        assert_eq!(shared.generation, 0);
        assert_eq!(progress.snapshot(item).unwrap().completed, 0);
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        assert_eq!(std::fs::read(&destination).unwrap(), [0x5a; 4096]);
    }
}
