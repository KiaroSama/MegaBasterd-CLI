//! Exact source command variants at the production API retry-policy seam.
#![allow(clippy::unwrap_used)]

use super::*;

fn mutations() -> [Value; 9] {
    [
        json!({"a":"p","t":"parent","n":[{"h":"tok","t":0,"a":"x","k":"y"}]}),
        json!({"a":"p","t":"parent","n":[{"h":"xxxxxxxx","t":1,"a":"x","k":"y"}]}),
        json!({"a":"d","n":"handle"}),
        json!({"a":"m","n":"handle","t":"newparent"}),
        json!({"a":"a","n":"handle","attr":"x","key":"y"}),
        json!({"a":"l","n":"handle"}),
        json!({"a":"p","t":"parent","n":[{"h":"src","t":0,"a":"x","k":"y"}]}),
        json!({"a":"sml"}),
        json!({"a":"u","s":1024}),
    ]
}

fn accepted(command: &Value) -> Value {
    match command["a"].as_str().unwrap() {
        "p" => json!({"f":[{"h":"new"}]}),
        "l" => json!("publichandle"),
        "u" => json!({"p":"https://upload.mega.nz/slot"}),
        _ => json!(0),
    }
}

#[test]
fn every_source_mutation_is_sent_once_after_timeout_or_connection_drop() {
    for command in mutations() {
        for timeout in [false, true] {
            let mut calls = 0;
            let mut waits = 0;
            let error = tests::api()
                .request_with(
                    command.clone(),
                    &[],
                    |_, _, body, payload| {
                        calls += 1;
                        assert_eq!(payload, &json!([command.clone()]));
                        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), *payload);
                        Err(AttemptFailure::after(if timeout {
                            Error::Timeout
                        } else {
                            Error::Io(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "response lost",
                            ))
                        }))
                    },
                    |_| {
                        waits += 1;
                        Ok(())
                    },
                )
                .unwrap_err();
            assert!(matches!(error, Error::AmbiguousMutation(_)));
            assert_eq!(error.exit_code(), 1);
            assert_eq!((calls, waits), (1, 0));
            assert!(!error.to_string().contains("parent"));
            assert!(!error.to_string().contains("handle"));
        }
    }
}

#[test]
fn ambiguous_errors_name_only_allowlisted_actions_and_never_the_payload() {
    for (command, label) in [
        (json!({"a":"d","n":"handle"}), "d"),
        (
            json!({"a":"p","t":"private-parent","n":[{"k":"private-key"}]}),
            "p",
        ),
        (
            json!({"a":"private-action-sentinel","n":"handle"}),
            "unknown",
        ),
        (
            json!({"a":"d\r\nprivate-action-sentinel","n":"handle"}),
            "unknown",
        ),
        (json!({"n":"handle"}), "unknown"),
        (
            json!([{"a":"d","n":"handle"},{"a":"p","t":"private-parent"}]),
            "batch",
        ),
    ] {
        let mut calls = 0;
        let error = tests::api()
            .request_with(
                command,
                &[],
                |_, _, _, _| {
                    calls += 1;
                    Err(AttemptFailure::after(Error::Timeout))
                },
                |_| panic!("an ambiguous mutation used retry backoff"),
            )
            .unwrap_err();
        assert!(matches!(&error, Error::AmbiguousMutation(_)));
        assert_eq!(error.code(), "ambiguous_mutation");
        assert_eq!(error.exit_code(), 1);
        assert!(!error.retryable_network());
        assert_eq!(calls, 1);
        let message = error.to_string();
        assert!(message.contains(&format!("({label})")));
        assert!(message.contains("not replayed"));
        assert!(message.contains("Recheck remote state"));
        for secret in [
            "handle",
            "private-parent",
            "private-key",
            "private-action-sentinel",
            "\r",
            "\n",
        ] {
            assert!(!message.contains(secret));
            assert!(!format!("{error:?}").contains(secret));
        }
    }
}

#[test]
fn every_source_mutation_can_retry_a_proven_presend_timeout() {
    for command in mutations() {
        let expected = accepted(&command);
        let mut calls = 0;
        let mut waits = Vec::new();
        let result = tests::api().request_with(
            command.clone(),
            &[],
            |_, _, _, payload| {
                calls += 1;
                assert_eq!(payload, &json!([command.clone()]));
                if calls == 1 {
                    Err(AttemptFailure {
                        error: Error::Timeout,
                        sent: false,
                    })
                } else {
                    parse_response(
                        &serde_json::to_vec(&json!([expected.clone()])).unwrap(),
                        payload,
                    )
                    .map(Exchange::Result)
                    .map_err(AttemptFailure::after)
                }
            },
            |duration| {
                waits.push(duration.as_secs());
                Ok(())
            },
        );
        assert_eq!(result.unwrap(), expected);
        assert_eq!(calls, 2);
        assert_eq!(waits, [2]);
    }
}

#[test]
fn every_source_mutation_retries_definitive_rate_limit_but_stops_at_five() {
    for command in mutations() {
        for exhausted in [false, true] {
            let expected = accepted(&command);
            let mut calls = 0;
            let mut waits = Vec::new();
            let result = tests::api().request_with(
                command.clone(),
                &[],
                |_, _, _, payload| {
                    calls += 1;
                    let response = if exhausted || calls == 1 {
                        json!(-4)
                    } else {
                        json!([expected.clone()])
                    };
                    parse_response(&serde_json::to_vec(&response).unwrap(), payload)
                        .map(Exchange::Result)
                        .map_err(AttemptFailure::after)
                },
                |duration| {
                    waits.push(duration.as_secs());
                    Ok(())
                },
            );
            if exhausted {
                assert!(matches!(result, Err(Error::Mega { code: -4, .. })));
                assert_eq!(calls, 5);
                assert_eq!(waits, [2, 4, 8, 16]);
            } else {
                assert_eq!(result.unwrap(), expected);
                assert_eq!(calls, 2);
                assert_eq!(waits, [2]);
            }
        }
    }
}

#[test]
fn all_source_reads_retry_timeouts_and_resets_with_exact_attempt_limits() {
    for command in [
        json!({"a":"ug"}),
        json!({"a":"uq","strg":1}),
        json!({"a":"g","g":1,"p":"id"}),
        json!({"a":"f","c":1}),
    ] {
        for (timeout, failures) in [(true, 2), (false, 1), (true, 5)] {
            let mut calls = 0;
            let mut waits = Vec::new();
            let result = tests::api().request_with(
                command.clone(),
                &[],
                |_, _, _, payload| {
                    calls += 1;
                    assert_eq!(payload, &json!([command.clone()]));
                    if calls <= failures {
                        Err(AttemptFailure::after(if timeout {
                            Error::Timeout
                        } else {
                            Error::Io(io::Error::new(io::ErrorKind::ConnectionReset, "dropped"))
                        }))
                    } else {
                        parse_response(br#"[{"ok":true}]"#, payload)
                            .map(Exchange::Result)
                            .map_err(AttemptFailure::after)
                    }
                },
                |duration| {
                    waits.push(duration.as_secs());
                    Ok(())
                },
            );
            if failures == 5 {
                assert!(matches!(result, Err(Error::Timeout)));
                assert_eq!(calls, 5);
                assert_eq!(waits, [2, 4, 8, 16]);
            } else {
                assert_eq!(result.unwrap(), json!({"ok":true}));
                assert_eq!(calls, failures + 1);
                assert_eq!(waits, if timeout { vec![2, 4] } else { vec![2] });
            }
        }
    }
}

#[test]
fn successful_create_folder_returns_only_its_confirmed_result_and_is_sent_once() {
    let command = mutations()[1].clone();
    let mut calls = 0;
    let result = tests::api()
        .request_with(
            command.clone(),
            &[],
            |_, _, _, payload| {
                calls += 1;
                assert_eq!(payload, &json!([command.clone()]));
                parse_response(br#"[{"f":[{"h":"new"}]}]"#, payload)
                    .map(Exchange::Result)
                    .map_err(AttemptFailure::after)
            },
            |_| panic!("a successful mutation waited for a retry"),
        )
        .unwrap();
    assert_eq!(result, json!({"f":[{"h":"new"}]}));
    assert_eq!(calls, 1);
}
