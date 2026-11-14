//! Observe the kernel-selected local IPv4 route without sending a datagram or resolving a host.
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

pub(crate) fn local_route() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(SocketAddr::from(([192, 0, 2, 1], 9))).ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

#[cfg(test)]
mod tests {
    #[test]
    fn route_probe_uses_only_numeric_udp_route_selection_without_payload_io() {
        let production = include_str!("route.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let expected = r"
            use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
            pub(crate) fn local_route() -> Option<IpAddr> {
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
                socket.connect(SocketAddr::from(([192, 0, 2, 1], 9))).ok()?;
                socket.local_addr().ok().map(|address| address.ip())
            }
        ";
        let actual = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected.split_whitespace().collect::<Vec<_>>());
    }

    #[test]
    fn unavailable_route_is_optional_and_never_requires_a_remote_service() {
        if let Some(route) = super::local_route() {
            assert!(route.is_ipv4());
            assert!(!route.is_unspecified());
        }
    }
}
