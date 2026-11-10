use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public(IpAddr::V4(mapped));
            }
            let [a, b, c, d, e, f, g, h] = ip.segments();
            // IANA 2001::/23 is special-purpose, with these explicit global exceptions.
            let global_protocol = (b == 1 && [c, d, e, f, g] == [0; 5] && (1..=3).contains(&h))
                || b == 3
                || (b == 4 && c == 0x112)
                || (0x20..=0x3f).contains(&b);
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && b < 0x200 && !global_protocol)
                && !(a == 0x2001 && b == 0xdb8)
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

pub struct SafeResolver {
    state: Arc<OnceLock<TokioResolver>>,
    trusted_proxy_host: Option<String>,
    timeout: Duration,
}

impl SafeResolver {
    pub fn new(timeout: Duration, trusted_proxy_host: Option<String>) -> Self {
        Self {
            state: Arc::new(OnceLock::new()),
            timeout,
            trusted_proxy_host,
        }
    }
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        self.resolve_name(name.as_str())
    }
}

impl SafeResolver {
    pub fn resolve_name(&self, name: &str) -> Resolving {
        let name = name.to_owned();
        let state = self.state.clone();
        let trusted = self
            .trusted_proxy_host
            .as_ref()
            .is_some_and(|host| host.eq_ignore_ascii_case(&name));
        let timeout = self.timeout;
        Box::pin(async move {
            if state.get().is_none() {
                let mut builder = TokioResolver::builder_tokio()?;
                builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
                let resolver = builder.build()?;
                let _ = state.set(resolver);
            }
            let resolver = state
                .get()
                .ok_or_else(|| io::Error::other("DNS initialization failed"))?;
            let hostname = format!("{}.", name.as_str().trim_end_matches('.'));
            let lookup = tokio::time::timeout(timeout, resolver.lookup_ip(hostname))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "DNS lookup exceeded its deadline")
                })??;
            let addresses: Vec<_> = lookup.iter().collect();
            if addresses.is_empty() || (!trusted && addresses.iter().any(|ip| !is_public(*ip))) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Destination resolves to an unsafe address",
                )
                .into());
            }
            let addresses: Addrs = Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addresses)
        })
    }
}
