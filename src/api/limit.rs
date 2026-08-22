//! Per-IP rate limiting for the hosted surface.
//!
//! A local inspector needs none of this — it serves one operator on
//! loopback. Hosted serves strangers, and every route behind the guard
//! can make the process dial an arbitrary URL, so an unlimited caller
//! is an amplifier.
//!
//! This is a token bucket rather than a dependency on the control
//! plane's identical one: `mcpg-control-plane-core` defaults to
//! `sqlx/sqlite`, and a database driver has no business in a debugging
//! tool for the sake of forty lines. The shapes are deliberately the
//! same (per-minute rate, burst, optional proxy trust) so the two read
//! alike if they ever do merge.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    /// `per_min` sustained requests per IP with a `burst` allowance.
    /// `per_min == 0` disables limiting entirely — the local default,
    /// where the only caller is the operator who started the process.
    pub fn new(per_min: u32, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: burst.max(1) as f64,
            refill_per_sec: per_min as f64 / 60.0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.refill_per_sec > 0.0
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// Split out so the refill maths is testable without sleeping.
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled() {
            return true;
        }
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        // A long-idle process would otherwise accumulate one entry per
        // IP that ever called; drop the ones that have refilled fully,
        // since they are indistinguishable from new.
        if buckets.len() > 10_000 {
            buckets.retain(|_, b| {
                let refilled = b.tokens
                    + now.saturating_duration_since(b.last).as_secs_f64() * self.refill_per_sec;
                refilled < self.capacity
            });
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn a_zero_rate_disables_limiting() {
        let limiter = RateLimiter::new(0, 0);
        assert!(!limiter.enabled());
        for _ in 0..1000 {
            assert!(limiter.check(ip(1)));
        }
    }

    #[test]
    fn burst_is_spent_then_refilled_over_time() {
        // 60/min = 1/sec, burst 3.
        let limiter = RateLimiter::new(60, 3);
        let start = Instant::now();
        assert!(limiter.check_at(ip(1), start));
        assert!(limiter.check_at(ip(1), start));
        assert!(limiter.check_at(ip(1), start));
        assert!(!limiter.check_at(ip(1), start), "burst exhausted");

        // One second later exactly one token is back.
        let later = start + Duration::from_secs(1);
        assert!(limiter.check_at(ip(1), later));
        assert!(!limiter.check_at(ip(1), later));
    }

    #[test]
    fn buckets_are_per_ip() {
        let limiter = RateLimiter::new(60, 1);
        let now = Instant::now();
        assert!(limiter.check_at(ip(1), now));
        assert!(!limiter.check_at(ip(1), now));
        // A different caller is unaffected by the first one's spending.
        assert!(limiter.check_at(ip(2), now));
    }
}
