use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use crate::error::{Error, Result, poisoned};

pub struct QuotaLedger(Mutex<BTreeMap<String, u64>>);

impl QuotaLedger {
    pub fn new(free: BTreeMap<String, u64>) -> Self {
        Self(Mutex::new(free))
    }

    pub fn reserve(&self, size: u64, exclude: &HashSet<String>) -> Result<Option<String>> {
        let mut free = self.0.lock().map_err(poisoned)?;
        let selected = free
            .iter()
            .filter(|(email, amount)| **amount >= size && !exclude.contains(*email))
            .max_by(|(left_email, left_amount), (right_email, right_amount)| {
                left_amount
                    .cmp(right_amount)
                    .then_with(|| left_email.cmp(right_email))
            })
            .map(|(email, _)| email.clone());
        if let Some(email) = &selected {
            let available = free
                .get_mut(email)
                .ok_or_else(|| Error::protocol("Quota reservation lost its account"))?;
            *available -= size;
        }
        Ok(selected)
    }

    pub fn release(&self, email: &str, size: u64) -> Result<()> {
        if let Some(amount) = self.0.lock().map_err(poisoned)?.get_mut(email) {
            *amount = amount
                .checked_add(size)
                .ok_or_else(|| Error::protocol("Quota release overflows"))?;
        }
        Ok(())
    }

    pub fn reconcile(&self, email: &str, live_free: u64) -> Result<()> {
        // A live quota cannot see reservations still in flight. Never increase available space here.
        let mut free = self.0.lock().map_err(poisoned)?;
        let amount = free.entry(email.to_owned()).or_default();
        *amount = (*amount).min(live_free);
        Ok(())
    }

    pub fn free(&self, email: &str) -> Result<Option<u64>> {
        Ok(self.0.lock().map_err(poisoned)?.get(email).copied())
    }
}
