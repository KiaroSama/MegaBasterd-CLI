//! Definitive quota recovery preserves a finite attempt budget and the selected routing policy.
use std::time::Duration;

use super::{control::Control, download::DownloadOptions};
use crate::{
    error::{Error, Result},
    storage::proxies::Routing,
};

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;

pub(crate) fn retry<T>(
    options: &DownloadOptions,
    routing: &Routing,
    control: &Control,
    action: impl FnMut() -> Result<T>,
) -> Result<T> {
    retry_with(
        options,
        control,
        action,
        || match &routing.pool {
            Some(pool) => pool.has_available(),
            None => Ok(false),
        },
        |duration| {
            wait_with(duration, control, crate::platform::local_route, |tick| {
                control.wait(tick)
            })
        },
    )
}

fn retry_with<T>(
    options: &DownloadOptions,
    control: &Control,
    mut action: impl FnMut() -> Result<T>,
    mut available: impl FnMut() -> Result<bool>,
    mut wait: impl FnMut(Duration) -> Result<()>,
) -> Result<T> {
    let attempts = options.quota_attempts.max(1);
    let mut escalated = false;
    for attempt in 0..attempts {
        control.checkpoint()?;
        match action() {
            Err(
                error @ Error::Mega {
                    code: -17 | -24, ..
                },
            ) => {
                control.checkpoint()?;
                if options.quota_wait == 0 || attempt == attempts - 1 {
                    return Err(error);
                }
                if !escalated && available()? {
                    escalated = true;
                    continue;
                }
                wait(Duration::from_secs(options.quota_wait))?;
            }
            result => return result,
        }
    }
    Err(Error::Timeout)
}

fn wait_with(
    duration: Duration,
    control: &Control,
    mut route: impl FnMut() -> Option<std::net::IpAddr>,
    mut wait: impl FnMut(Duration) -> Result<()>,
) -> Result<()> {
    control.checkpoint()?;
    let baseline = route();
    let mut remaining = duration;
    while !remaining.is_zero() {
        let tick = remaining.min(Duration::from_secs(2));
        wait(tick)?;
        control.checkpoint()?;
        remaining -= tick;
        if let Some(baseline) = baseline
            && route().is_some_and(|current| current != baseline)
        {
            return Ok(());
        }
    }
    Ok(())
}
