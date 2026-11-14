use std::sync::{Arc, Mutex, OnceLock};

use crate::{
    error::{Error, Result, poisoned},
    transfers::control::Control,
};

static SIGNAL: OnceLock<Arc<Mutex<Option<Control>>>> = OnceLock::new();
static INITIALIZE: Mutex<()> = Mutex::new(());

pub(crate) struct Scope<'a> {
    current: &'a Mutex<Option<Control>>,
    previous: Option<Control>,
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *current = self.previous.take();
    }
}

fn enter<'a>(current: &'a Mutex<Option<Control>>, control: &Control) -> Result<Scope<'a>> {
    let previous = current.lock().map_err(poisoned)?.replace(control.clone());
    Ok(Scope { current, previous })
}

fn cancel(current: &Mutex<Option<Control>>) {
    let current = current.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(control) = &*current {
        control.cancel();
    }
}

pub(crate) fn current() -> Result<Option<Control>> {
    SIGNAL.get().map_or(Ok(None), |current| {
        Ok(current.lock().map_err(poisoned)?.clone())
    })
}

pub(crate) fn activate(control: &Control) -> Result<Scope<'static>> {
    let _initialize = INITIALIZE.lock().map_err(poisoned)?;
    if SIGNAL.get().is_none() {
        let current = Arc::new(Mutex::new(None::<Control>));
        let signal = current.clone();
        ctrlc::try_set_handler(move || cancel(&signal))
            .map_err(|_| Error::protocol("Could not install the native cancellation handler"))?;
        let _ = SIGNAL.set(current);
    }
    let current = SIGNAL
        .get()
        .ok_or_else(|| Error::protocol("Cancellation handler is unavailable"))?;
    enter(current, control)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn nested_command_routes_restore_the_parent_after_return_and_unwind_without_resetting_cancel() {
        let current = Mutex::new(None);
        let menu = Control::new();
        let child = Control::new();
        {
            let _menu = enter(&current, &menu).unwrap();
            {
                let _child = enter(&current, &child).unwrap();
                cancel(&current);
                assert!(child.is_canceled() && !menu.is_canceled());
            }
            let next = Control::new();
            let outcome = std::panic::catch_unwind(|| {
                let _child = enter(&current, &next).unwrap();
                std::panic::resume_unwind(Box::new(()));
            });
            assert!(outcome.is_err());
            assert!(!next.is_canceled());
            cancel(&current);
            assert!(menu.is_canceled() && child.is_canceled());
            assert_eq!(menu.checkpoint().unwrap_err().exit_code(), 130);
        }
        assert!(current.lock().unwrap().is_none());
        cancel(&current);
        assert!(menu.is_canceled() && child.is_canceled() && !Control::new().is_canceled());
    }
}
