use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use std::io;
use url::Url;
use zeroize::Zeroizing;

use super::hashcash::Challenge;
use super::transport::{AttemptFailure, Reply, Transport};
use crate::error::{Error, Result};
use crate::transfers::control::Control;

pub const API_URL: &str = "https://g.api.mega.co.nz/cs";
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const APP_KEY: &str = "BdARkQSQ";

#[cfg(test)]
#[path = "api_body_tests.rs"]
mod body_tests;
#[cfg(test)]
#[path = "api_hashcash_peer_tests.rs"]
mod hashcash_peer_tests;
#[cfg(test)]
#[path = "api_hashcash_tests.rs"]
mod hashcash_tests;
#[cfg(test)]
#[path = "api_response_peer_tests.rs"]
mod response_peer_tests;
#[cfg(test)]
#[path = "api_retry_peer_tests.rs"]
mod retry_peer_tests;
#[cfg(test)]
#[path = "api_retry_policy_tests.rs"]
mod retry_policy_tests;

pub fn is_mutating(value: &Value) -> bool {
    fn read_only(value: &Value) -> bool {
        matches!(
            value.get("a").and_then(Value::as_str),
            Some("ug" | "uq" | "g" | "f" | "us0" | "us")
        )
    }
    match value.as_array() {
        Some(commands) => commands.is_empty() || commands.iter().any(|command| !read_only(command)),
        None => !read_only(value),
    }
}

fn ambiguous_mutation(payload: &Value) -> Error {
    let action = match payload.as_array().map(Vec::as_slice) {
        Some([command]) => match command.get("a").and_then(Value::as_str) {
            Some("p") => "p",
            Some("d") => "d",
            Some("m") => "m",
            Some("a") => "a",
            Some("l") => "l",
            Some("u") => "u",
            Some("sml") => "sml",
            Some("ufa") => "ufa",
            Some("pfa") => "pfa",
            _ => "unknown",
        },
        _ => "batch",
    };
    Error::AmbiguousMutation(action)
}

enum Exchange {
    Result(Value),
    Challenge(Challenge),
}

fn transient(error: &Error) -> bool {
    match error {
        Error::Http(error) => crate::error::retryable_http(error),
        Error::Io(error) => match error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
        {
            Some(cause) => crate::error::retryable_http(cause),
            None => matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::Interrupted
            ),
        },
        Error::Timeout => true,
        _ => false,
    }
}

fn read_reply(mut reply: Reply, payload: &Value, limit: u64) -> Result<Exchange> {
    if reply.response.status().as_u16() == 402 {
        let header = reply
            .response
            .headers()
            .get("X-Hashcash")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::protocol("MEGA requested Hashcash without a challenge"))?;
        return Ok(Exchange::Challenge(Challenge::parse(header)?));
    }
    if !reply.response.status().is_success() {
        return Err(Error::protocol(format!(
            "MEGA API returned HTTP {}",
            reply.response.status().as_u16()
        )));
    }
    let result = (|| {
        if let Some(kind) = reply
            .response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            && !kind.to_ascii_lowercase().contains("json")
        {
            let message = if kind
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))
            {
                "MEGA API returned text/html instead of JSON"
            } else {
                "MEGA API returned a non-JSON content type"
            };
            return Err(Error::protocol(message));
        }
        let bytes = reply.bytes(limit)?;
        parse_response(&bytes, payload)
    })();
    match result {
        Ok(data) => {
            reply.credit()?;
            Ok(Exchange::Result(data))
        }
        Err(error @ Error::Mega { .. }) => Err(error),
        Err(error) => {
            let _ = reply.malformed();
            Err(error)
        }
    }
}

fn parse_response(bytes: &[u8], payload: &Value) -> Result<Value> {
    let data: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::protocol("MEGA API returned invalid JSON"))?;
    if let Some(code) = data.as_i64().filter(|code| *code < 0) {
        return Err(Error::mega(code));
    }
    let commands = payload
        .as_array()
        .ok_or_else(|| Error::invalid("API commands are not an array"))?;
    let items = data.as_array().ok_or_else(|| {
        Error::protocol(if data.is_object() {
            "MEGA API returned a JSON object where an array of results was expected"
        } else {
            "MEGA API returned a non-array result"
        })
    })?;
    if items.is_empty() || items.len() != commands.len() {
        return Err(Error::protocol(
            "MEGA API result count does not match the request",
        ));
    }
    let all_rejected = items
        .iter()
        .all(|item| item.as_i64().is_some_and(|code| code < 0));
    let failures = || {
        items
            .iter()
            .filter_map(Value::as_i64)
            .filter(|code| *code < 0)
    };
    if let Some(code) = failures()
        .find(|code| *code != -4)
        .or_else(|| failures().next())
    {
        // A per-command error cannot authorize replaying successful mutations in the same batch.
        if items.len() > 1 && is_mutating(payload) && !all_rejected {
            return Err(ambiguous_mutation(payload));
        }
        return Err(Error::mega(code));
    }
    for (command, item) in commands.iter().zip(items) {
        let valid = match command.get("a").and_then(Value::as_str) {
            Some("d" | "m" | "a" | "sml") => item.as_i64() == Some(0),
            Some("ufa") => item
                .get("p")
                .and_then(Value::as_str)
                .is_some_and(|url| !url.is_empty()),
            Some("pfa") => {
                item.as_i64() == Some(0)
                    || item
                        .as_str()
                        .is_some_and(|attributes| !attributes.is_empty())
            }
            Some("l") if command.get("d").and_then(Value::as_u64) == Some(1) => {
                item.as_i64() == Some(0)
            }
            Some("l") => item.as_str().is_some_and(|h| !h.is_empty()),
            Some("p") => item
                .get("f")
                .and_then(Value::as_array)
                .is_some_and(|nodes| {
                    !nodes.is_empty()
                        && nodes.iter().all(|node| {
                            node.get("h")
                                .and_then(Value::as_str)
                                .is_some_and(|h| !h.is_empty())
                        })
                }),
            Some("u") => item
                .get("p")
                .and_then(Value::as_str)
                .is_some_and(|p| !p.is_empty()),
            Some("ug" | "uq" | "g" | "f" | "us0" | "us") => item.is_object(),
            _ => item.is_object() || item.is_string() || item.as_i64() == Some(0),
        };
        if !valid {
            return Err(Error::protocol(
                "MEGA returned an invalid result for its action",
            ));
        }
    }
    Ok(data)
}

pub struct Api {
    pub transport: Transport,
    base: Url,
    sequence: u64,
    sid: Option<Zeroizing<String>>,
    pub control: Control,
    #[cfg(test)]
    test_backoffs: Option<std::sync::mpsc::SyncSender<Duration>>,
}

impl Api {
    pub fn new(transport: Transport, control: Control) -> Result<Self> {
        Ok(Self {
            transport,
            base: Url::parse(API_URL)
                .map_err(|_| Error::protocol("Invalid built-in API origin"))?,
            sequence: 0,
            sid: None,
            control,
            #[cfg(test)]
            test_backoffs: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_peer(address: std::net::SocketAddr) -> Result<Self> {
        let control = Control::new();
        let mut api = Self::new(Transport::test_peer(address, control.clone())?, control)?;
        api.base = Url::parse(&format!("https://testserver.com:{}/cs", address.port()))
            .map_err(|_| Error::invalid("Test API endpoint is invalid"))?;
        Ok(api)
    }

    #[cfg(test)]
    pub(crate) fn observe_backoffs(&mut self, sender: std::sync::mpsc::SyncSender<Duration>) {
        assert_eq!(self.base.host_str(), Some("testserver.com"));
        self.test_backoffs = Some(sender);
    }

    pub fn set_session(&mut self, sid: &str) {
        self.sid = Some(Zeroizing::new(sid.to_owned()));
    }
    pub fn clear_session(&mut self) {
        self.sid = None;
    }
    pub fn fork(&self) -> Result<Self> {
        let mut client = Self::new(self.transport.clone(), self.control.clone())?;
        client.base = self.base.clone();
        #[cfg(test)]
        {
            client.test_backoffs = self.test_backoffs.clone();
        }
        if let Some(sid) = &self.sid {
            client.set_session(sid);
        }
        Ok(client)
    }

    pub fn request(&mut self, command: Value, extra: &[(&str, &str)]) -> Result<Value> {
        let transport = self.transport.clone();
        let control = self.control.clone();
        #[cfg(test)]
        let backoffs = self.test_backoffs.clone();
        self.request_with(
            command,
            extra,
            move |url, headers, body, payload| {
                let reply = transport.send_api(url, headers, body)?;
                read_reply(reply, payload, MAX_RESPONSE_BYTES).map_err(AttemptFailure::after)
            },
            move |duration| {
                #[cfg(test)]
                if let Some(backoffs) = &backoffs {
                    control.checkpoint()?;
                    backoffs.try_send(duration).map_err(|_| {
                        Error::protocol("Fixture retry observer exceeded its bound")
                    })?;
                    return Ok(());
                }
                control.wait(duration)
            },
        )
    }

    fn request_with(
        &mut self,
        command: Value,
        extra: &[(&str, &str)],
        exchange: impl FnMut(
            Url,
            HeaderMap,
            &[u8],
            &Value,
        ) -> std::result::Result<Exchange, AttemptFailure>,
        wait: impl FnMut(Duration) -> Result<()>,
    ) -> Result<Value> {
        self.request_with_hashcash(
            command,
            extra,
            exchange,
            wait,
            (Instant::now, Challenge::solve),
        )
    }

    fn request_with_hashcash(
        &mut self,
        command: Value,
        extra: &[(&str, &str)],
        mut exchange: impl FnMut(
            Url,
            HeaderMap,
            &[u8],
            &Value,
        ) -> std::result::Result<Exchange, AttemptFailure>,
        mut wait: impl FnMut(Duration) -> Result<()>,
        (mut now, mut solve): (
            impl FnMut() -> Instant,
            impl FnMut(&Challenge, Instant, &Control) -> Result<String>,
        ),
    ) -> Result<Value> {
        let single = !command.is_array();
        let payload = if single { json!([command]) } else { command };
        if payload
            .as_array()
            .is_none_or(|items| items.is_empty() || items.iter().any(|item| !item.is_object()))
        {
            return Err(Error::invalid(
                "API request requires a nonempty array of commands",
            ));
        }
        let mutating = is_mutating(&payload);
        let body = Zeroizing::new(serde_json::to_vec(&payload)?);
        let deadline = now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| Error::invalid("Hashcash deadline overflows"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let mut challenges = 0;
        for attempt in 0..5u32 {
            if challenges == 0 {
                self.control.checkpoint()?;
            } else {
                self.control.checkpoint_until(deadline)?;
                if now() >= deadline {
                    return Err(Error::Timeout);
                }
            }
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| Error::protocol("API sequence exhausted"))?;
            let mut url = self.base.clone();
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("id", &self.sequence.to_string())
                    .append_pair("ak", APP_KEY);
                if let Some(sid) = &self.sid {
                    query.append_pair("sid", sid);
                }
                for &(key, value) in extra {
                    query.append_pair(key, value);
                }
            }
            match exchange(url, headers.clone(), &body, &payload) {
                Ok(Exchange::Result(data)) => {
                    return Ok(if single { data[0].clone() } else { data });
                }
                Ok(Exchange::Challenge(challenge)) => {
                    challenges += 1;
                    self.control.checkpoint_until(deadline)?;
                    if challenges > 2 || now() >= deadline {
                        return Err(Error::Timeout);
                    }
                    let solution = solve(&challenge, deadline, &self.control)?;
                    self.control.checkpoint_until(deadline)?;
                    if now() >= deadline {
                        return Err(Error::Timeout);
                    }
                    let mut solution = HeaderValue::from_str(&solution)
                        .map_err(|_| Error::protocol("Hashcash solution is invalid"))?;
                    solution.set_sensitive(true);
                    headers.insert("X-Hashcash", solution);
                }
                Err(failure) => {
                    let rate_limited = matches!(failure.error, Error::Mega { code: -4, .. });
                    if mutating && failure.sent && !matches!(failure.error, Error::Mega { .. }) {
                        return Err(ambiguous_mutation(&payload));
                    }
                    if attempt < 4
                        && (rate_limited
                            || ((!mutating || !failure.sent) && transient(&failure.error)))
                    {
                        wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                    } else {
                        return Err(failure.error);
                    }
                }
            }
        }
        Err(Error::Timeout)
    }
}

pub fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| Error::protocol(format!("MEGA response is missing {name}")))
}

pub fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| Error::protocol(format!("MEGA field {name} is not text")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::storage::proxies::Routing;
    use std::io;

    pub(super) fn api() -> Api {
        let control = Control::new();
        Api::new(
            Transport::new(
                Routing {
                    explicit: None,
                    pool: None,
                    force: false,
                },
                Duration::from_secs(1),
                "contract".into(),
                control.clone(),
            )
            .unwrap(),
            control,
        )
        .unwrap()
    }

    #[test]
    fn interrupted_body_never_replays_a_mutation_but_a_read_can_recover() {
        for action in ["p", "d", "m", "a", "l", "u", "sml", "future_action", "g"] {
            let mut calls = 0;
            let result = api().request_with(
                json!({"a":action}),
                &[],
                |_, _, _, _| {
                    calls += 1;
                    if calls == 1 {
                        Err(AttemptFailure::after(Error::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "body interrupted",
                        ))))
                    } else {
                        Ok(Exchange::Result(
                            json!([{"s":1,"g":"https://gfs.mega.nz/ticket"}]),
                        ))
                    }
                },
                |_| Ok(()),
            );
            if action == "g" {
                assert!(result.is_ok());
                assert_eq!(calls, 2);
            } else {
                assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
                assert_eq!(calls, 1);
            }
        }
    }

    #[test]
    fn unreadable_or_wrong_mutation_reply_is_ambiguous_without_replay() {
        for response in [
            &b"["[..],
            &b"[]"[..],
            &b"[null]"[..],
            &b"[{}]"[..],
            &b"[{\"f\":[]}]"[..],
        ] {
            let mut calls = 0;
            let payload = json!([{"a":"p"}]);
            let result = api().request_with(
                payload.clone(),
                &[],
                |_, _, _, _| {
                    calls += 1;
                    parse_response(response, &payload)
                        .map(Exchange::Result)
                        .map_err(AttemptFailure::after)
                },
                |_| Ok(()),
            );
            assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
            assert_eq!(calls, 1);
        }
        for failure in [
            Error::protocol("HTTP 503"),
            Error::protocol("non-JSON content"),
            Error::Timeout,
        ] {
            let mut failure = Some(failure);
            let result = api().request_with(
                json!({"a":"d"}),
                &[],
                |_, _, _, _| Err(AttemptFailure::after(failure.take().unwrap())),
                |_| Ok(()),
            );
            assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
        }
    }

    #[test]
    fn whole_request_rejection_can_retry_but_a_partially_committed_batch_cannot() {
        let mut calls = 0;
        let result = api().request_with(
            json!({"a":"d"}),
            &[],
            |_, _, _, _| {
                calls += 1;
                if calls == 1 {
                    Err(AttemptFailure::after(Error::mega(-4)))
                } else {
                    Ok(Exchange::Result(json!([0])))
                }
            },
            |_| Ok(()),
        );
        assert_eq!(result.unwrap(), json!(0));
        assert_eq!(calls, 2);
        let rejected = json!([{"a":"d"},{"a":"m"}]);
        let mut calls = 0;
        let result = api().request_with(
            rejected.clone(),
            &[],
            |_, _, _, _| {
                calls += 1;
                parse_response(b"[-4,-11]", &rejected)
                    .map(Exchange::Result)
                    .map_err(AttemptFailure::after)
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(Error::Mega { code: -11, .. })));
        assert_eq!(calls, 1);
        let payload = json!([{"a":"p"},{"a":"d"}]);
        let mut calls = 0;
        let result = api().request_with(
            payload.clone(),
            &[],
            |_, _, _, _| {
                calls += 1;
                parse_response(br#"[{"f":[{"h":"created"}]},-4]"#, &payload)
                    .map(Exchange::Result)
                    .map_err(AttemptFailure::after)
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
        assert_eq!(calls, 1);
    }

    #[test]
    fn retries_are_bounded_and_presend_policy_refusal_is_not_ambiguity() {
        let mut calls = 0;
        let result = api().request_with(
            json!({"a":"f"}),
            &[],
            |_, _, _, _| {
                calls += 1;
                Err(AttemptFailure::after(Error::Io(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "reset",
                ))))
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(calls, 5);
        let result = api().request_with(
            json!({"a":"p"}),
            &[],
            |_, _, _, _| {
                Err(AttemptFailure {
                    error: Error::protocol("Force-proxy has no route"),
                    sent: false,
                })
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(Error::Protocol(_))));
        let mut calls = 0;
        let result = api().request_with(
            json!({"a":"p"}),
            &[],
            |_, _, _, _| {
                calls += 1;
                if calls == 1 {
                    Err(AttemptFailure {
                        error: Error::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connect timeout",
                        )),
                        sent: false,
                    })
                } else {
                    Ok(Exchange::Result(json!([{"f":[{"h":"created"}]}])))
                }
            },
            |_| Ok(()),
        );
        assert!(result.is_ok());
        assert_eq!(calls, 2);
    }

    #[test]
    fn exact_envelope_and_action_result_shapes_are_required() {
        for action in ["d", "m", "a", "sml"] {
            let payload = json!([{"a":action}]);
            assert_eq!(parse_response(b"[0]", &payload).unwrap(), json!([0]));
            for wrong in [
                &b"[null]"[..],
                &b"[true]"[..],
                &b"[{}]"[..],
                &b"[1]"[..],
                &b"[0,0]"[..],
            ] {
                assert!(parse_response(wrong, &payload).is_err());
            }
        }
        assert!(
            parse_response(
                br#"[{"p":"https://ul.mega.nz/ticket"}]"#,
                &json!([{"a":"u"}])
            )
            .is_ok()
        );
        assert!(parse_response(br#"[{"f":[{"h":"created"}]}]"#, &json!([{"a":"p"}])).is_ok());
        assert!(matches!(
            parse_response(b"[-11]", &json!([{"a":"p"}])),
            Err(Error::Mega { code: -11, .. })
        ));
        assert!(parse_response(b"[0]", &json!([{"a":"ug"}])).is_err());
    }
}
