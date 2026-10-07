//! Small in-process fixed-window rate limiter.
//!
//! This protects a single API instance. Deployments with several instances
//! should additionally rate limit at the reverse proxy (the bundled nginx
//! configuration does).

use crate::error::AppError;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

struct Bucket {
    count: u32,
    window_start: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Bucket>>,
}

const MAX_KEYS: usize = 200_000;

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one event for `key`; fails once `limit` events happened in `window`.
    pub fn check(&self, key: &str, limit: u32, window: Duration) -> Result<(), AppError> {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_KEYS {
            // Memory-exhaustion guard: drop expired entries, and if still full
            // drop everything older than half the window.
            map.retain(|_, b| now.duration_since(b.window_start) < window);
            if map.len() >= MAX_KEYS {
                map.clear();
            }
        }
        let bucket = map
            .entry(key.to_string())
            .or_insert(Bucket { count: 0, window_start: now });
        if now.duration_since(bucket.window_start) >= window {
            bucket.count = 0;
            bucket.window_start = now;
        }
        if bucket.count >= limit {
            return Err(AppError::TooManyRequests);
        }
        bucket.count += 1;
        Ok(())
    }

    /// Remove buckets whose window ended more than `max_age` ago.
    pub fn purge(&self, max_age: Duration) {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, b| now.duration_since(b.window_start) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_limit_and_isolates_keys() {
        let rl = RateLimiter::new();
        let w = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(rl.check("a", 3, w).is_ok());
        }
        assert!(rl.check("a", 3, w).is_err());
        assert!(rl.check("b", 3, w).is_ok());
    }

    #[test]
    fn window_resets() {
        let rl = RateLimiter::new();
        let w = Duration::from_millis(30);
        assert!(rl.check("k", 1, w).is_ok());
        assert!(rl.check("k", 1, w).is_err());
        std::thread::sleep(Duration::from_millis(50));
        assert!(rl.check("k", 1, w).is_ok());
    }
}
