//! Bounded graceful refusals never wait for a saturated peer in the accept loop.
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};

use super::MAX_HEADER_BYTES;

const RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 5\r\nContent-Length: 27\r\n\r\nToo many active connections";
const CAPACITY: usize = 4;

#[derive(Default)]
pub(super) struct Refusals(Vec<Refusal>);

impl Refusals {
    pub(super) fn push(&mut self, socket: TcpStream) {
        if self.0.len() >= CAPACITY || socket.set_nonblocking(true).is_err() {
            let _ = socket.shutdown(Shutdown::Both);
            return;
        }
        self.0.push(Refusal {
            socket,
            sent: 0,
            half_closed: false,
            remaining: MAX_HEADER_BYTES,
            deadline: Instant::now() + Duration::from_millis(100),
        });
    }

    pub(super) fn poll(&mut self) {
        self.0
            .retain_mut(|refusal| refusal.advance().unwrap_or(false));
    }
}

struct Refusal {
    socket: TcpStream,
    sent: usize,
    half_closed: bool,
    remaining: usize,
    deadline: Instant,
}

impl Refusal {
    fn advance(&mut self) -> io::Result<bool> {
        if Instant::now() >= self.deadline {
            return Ok(false);
        }
        while self.sent != RESPONSE.len() {
            match self.socket.write(&RESPONSE[self.sent..]) {
                Ok(0) => return Ok(false),
                Ok(count) => self.sent += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        if !self.half_closed {
            self.socket.shutdown(Shutdown::Write)?;
            self.half_closed = true;
        }
        let mut bytes = [0; 4096];
        while self.remaining != 0 && Instant::now() < self.deadline {
            let wanted = bytes.len().min(self.remaining);
            match self.socket.read(&mut bytes[..wanted]) {
                Ok(0) => return Ok(false),
                Ok(count) => self.remaining -= count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }
}

impl Drop for Refusal {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn refusals_send_complete_503_without_waiting_for_fin_and_never_exceed_four_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mut refusals = Refusals::default();
        let mut clients = Vec::new();
        for _ in 0..CAPACITY {
            let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (socket, _) = listener.accept().unwrap();
            client
                .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            refusals.push(socket);
            refusals.0.last_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
            client.set_nonblocking(true).unwrap();
            let mut response = vec![0; RESPONSE.len()];
            let mut received = 0;
            let deadline = Instant::now() + Duration::from_secs(2);
            while received != response.len() {
                assert!(Instant::now() < deadline, "refusal response did not finish");
                refusals.poll();
                match client.read(&mut response[received..]) {
                    Ok(0) => panic!("refusal closed before the full response"),
                    Ok(count) => received += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => panic!("refusal response failed: {error}"),
                }
            }
            client.set_nonblocking(false).unwrap();
            let (head, body) =
                response.split_at(response.windows(4).position(|p| p == b"\r\n\r\n").unwrap() + 4);
            assert!(head.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
            assert!(
                std::str::from_utf8(head)
                    .unwrap()
                    .contains("Content-Length: 27\r\n")
            );
            assert_eq!(body, b"Too many active connections");
            // Keep every write half open: no closer may wait here for the client's FIN.
            clients.push(client);
        }
        assert_eq!(refusals.0.len(), CAPACITY);
        let mut excess = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (socket, _) = listener.accept().unwrap();
        refusals.push(socket);
        assert_eq!(refusals.0.len(), CAPACITY);
        match excess.read(&mut [0]) {
            Ok(0) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                ()
            }
            result => panic!("excess refusal retained an unbounded socket: {result:?}"),
        }
        // Force only the private closer deadlines, not a guessed sleep, then prove every owner retires.
        for refusal in &mut refusals.0 {
            refusal.deadline = Instant::now();
        }
        refusals.poll();
        assert!(refusals.0.is_empty());
        for mut client in clients {
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
        }
    }
}
