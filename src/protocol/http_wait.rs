//! Cooperative network waits retain a single deadline and drop pending I/O on cancellation.
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::{Duration, Instant},
};

use crate::{
    error::{Error, Result},
    transfers::control::Control,
};

#[cfg(test)]
std::thread_local! {
    static PENDING_OBSERVER: std::cell::RefCell<Option<std::sync::mpsc::SyncSender<()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) struct PendingObserver;

#[cfg(test)]
pub(super) fn observe_pending(sender: std::sync::mpsc::SyncSender<()>) -> PendingObserver {
    PENDING_OBSERVER.with(|observer| {
        assert!(
            observer.borrow_mut().replace(sender).is_none(),
            "pending I/O observer is already active"
        );
    });
    PendingObserver
}

#[cfg(test)]
impl PendingObserver {
    pub(super) fn notified(&self) -> bool {
        PENDING_OBSERVER.with(|observer| observer.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for PendingObserver {
    fn drop(&mut self) {
        PENDING_OBSERVER.with(|observer| {
            observer.borrow_mut().take();
        });
    }
}

pub(crate) async fn interruptible<T>(
    future: impl Future<Output = Result<T>>,
    deadline: Instant,
    control: &Control,
) -> Result<T> {
    let mut future = std::pin::pin!(future);
    let mut tick = std::pin::pin!(tokio::time::sleep(Duration::from_millis(100)));
    poll_fn(|cx| {
        if control.is_canceled() {
            return Poll::Ready(Err(Error::Canceled));
        }
        if Instant::now() >= deadline {
            return Poll::Ready(Err(Error::Timeout));
        }
        if let Poll::Ready(result) = future.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        #[cfg(test)]
        PENDING_OBSERVER.with(|observer| {
            if let Some(sender) = observer.borrow_mut().take() {
                assert!(
                    sender.try_send(()).is_ok(),
                    "pending I/O observer disconnected"
                );
            }
        });
        if tick.as_mut().poll(cx).is_ready() {
            tick.as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(100));
            let _ = tick.as_mut().poll(cx);
        }
        Poll::Pending
    })
    .await
}
