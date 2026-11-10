#![allow(clippy::unwrap_used)]

use megabasterd_cli::protocol::proxy_handshake::{connect, socks5};
use std::{
    io::{self, Cursor, Read, Write},
    net::SocketAddr,
};

struct Peer {
    input: Cursor<Vec<u8>>,
    sent: Vec<u8>,
}
impl Read for Peer {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}
impl Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.sent.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn peer(reply: &[u8]) -> Peer {
    Peer {
        input: Cursor::new(reply.to_vec()),
        sent: Vec::new(),
    }
}

#[test]
fn connect_uses_exact_numeric_destination_and_preserves_tunnel_bytes() {
    let target: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let mut peer = peer(b"HTTP/1.1 200 Connection Established\r\n\r\nTLS");
    connect(&mut peer, target, Some(("user", "synthetic"))).unwrap();
    let sent = String::from_utf8(peer.sent.clone()).unwrap();
    assert!(sent.starts_with("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n"));
    assert!(!sent.contains("443:443"));
    assert!(sent.contains("Proxy-Authorization: Basic dXNlcjpzeW50aGV0aWM="));
    let mut tail = String::new();
    peer.read_to_string(&mut tail).unwrap();
    assert_eq!(tail, "TLS");
    for reply in [
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
        b"HTTP/1.1 200 OK\n\n",
        b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Test: bad\x00value\r\n\r\n",
    ] {
        assert!(connect(&mut self::peer(reply), target, None).is_err());
    }
    assert!(connect(&mut self::peer(b""), "127.0.0.1:443".parse().unwrap(), None).is_err());
    for credentials in [("user:name", "password"), ("user", "pass\r\nword")] {
        let mut invalid = self::peer(b"");
        assert!(connect(&mut invalid, target, Some(credentials)).is_err());
        assert!(invalid.sent.is_empty());
    }
}

#[test]
fn socks_five_sends_numeric_ip_and_never_silently_drops_authentication() {
    let target: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let mut reply = peer(&[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    socks5(&mut reply, target, None).unwrap();
    assert_eq!(reply.sent, [5, 1, 0, 5, 1, 0, 1, 1, 1, 1, 1, 1, 187]);
    let mut denied = peer(&[5, 0]);
    assert!(socks5(&mut denied, target, Some(("user", "password"))).is_err());
    assert_eq!(denied.sent, [5, 1, 2]);
    for credentials in [("", "password"), ("user", ""), ("user", "pass\0word")] {
        let mut invalid = peer(b"");
        assert!(socks5(&mut invalid, target, Some(credentials)).is_err());
        assert!(invalid.sent.is_empty());
    }
    let mut ipv6 = peer(&[
        5, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    socks5(
        &mut ipv6,
        "[2606:4700:4700::1111]:443".parse().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(&ipv6.sent[..7], &[5, 1, 0, 5, 1, 0, 4]);
    assert_eq!(ipv6.sent.len(), 25);
}
