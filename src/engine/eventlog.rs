use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mcpg_mcp_client::tap::{FrameChannel, FrameDirection, FrameTap};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// One observed wire frame, exactly as sent or received.
///
/// Deserializable because an attached TUI reads these back off the API's
/// export endpoint — the same frames, having crossed a wire themselves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub direction: String,
    pub channel: String,
    pub body: String,
}

/// Bounded in-memory frame log with a live broadcast tail. Implements
/// the client's [`FrameTap`], so installing an `Arc<EventLog>` on a
/// connection records every frame; oldest frames drop first past the
/// cap. Late subscribers catch up from the buffer with
/// [`EventLog::since`], then follow the broadcast.
pub struct EventLog {
    events: Mutex<VecDeque<WireEvent>>,
    seq: AtomicU64,
    cap: usize,
    tx: broadcast::Sender<WireEvent>,
}

impl EventLog {
    pub fn new(cap: usize) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            events: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(1),
            cap: cap.max(1),
            tx,
        }
    }

    pub fn snapshot(&self) -> Vec<WireEvent> {
        self.events
            .lock()
            .expect("event log lock")
            .iter()
            .cloned()
            .collect()
    }

    /// Buffered events with `seq` greater than `after`. A browser
    /// reconnecting passes the last seq it rendered, so the SSE stream
    /// resumes without a gap (as far back as the ring buffer reaches).
    pub fn since(&self, after: u64) -> Vec<WireEvent> {
        self.events
            .lock()
            .expect("event log lock")
            .iter()
            .filter(|e| e.seq > after)
            .cloned()
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WireEvent> {
        self.tx.subscribe()
    }

    /// Append a frame that already happened, keeping its own sequence number
    /// and timestamp.
    ///
    /// For replaying a recording: the wire screen of a replay should be the
    /// wire of the original exchange, so re-stamping the frames with this
    /// process's clock would misdescribe them. The counter is advanced past
    /// what is replayed so a later live frame cannot collide with one.
    pub fn replay(&self, event: WireEvent) {
        self.seq.fetch_max(event.seq + 1, Ordering::Relaxed);
        {
            let mut events = self.events.lock().expect("event log lock");
            if events.len() >= self.cap {
                events.pop_front();
            }
            events.push_back(event.clone());
        }
        let _ = self.tx.send(event);
    }
}

impl FrameTap for EventLog {
    fn on_frame(&self, direction: FrameDirection, channel: FrameChannel, bytes: &[u8]) {
        let event = WireEvent {
            seq: self.seq.fetch_add(1, Ordering::Relaxed),
            ts_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            direction: direction.as_str().to_owned(),
            channel: channel.as_str().to_owned(),
            body: String::from_utf8_lossy(bytes).into_owned(),
        };
        {
            let mut events = self.events.lock().expect("event log lock");
            if events.len() >= self.cap {
                events.pop_front();
            }
            events.push_back(event.clone());
        }
        // No subscribers is the normal case (headless verbs); a full
        // channel drops for slow readers, who resync via `since`.
        let _ = self.tx.send(event);
    }
}

/// Frame tap that prints each frame to stderr as it happens — the
/// `--wire` flag of the one-shot verbs. Machine output stays on
/// stdout; this is human-facing chatter.
pub struct StderrWirePrinter;

impl FrameTap for StderrWirePrinter {
    fn on_frame(&self, direction: FrameDirection, channel: FrameChannel, bytes: &[u8]) {
        let body = String::from_utf8_lossy(bytes);
        eprintln!(
            "[wire {:>8} {:>13}] {}",
            direction.as_str(),
            channel.as_str(),
            body.trim_end()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_caps_and_orders() {
        let log = EventLog::new(2);
        log.on_frame(FrameDirection::Sent, FrameChannel::HttpRequest, b"a");
        log.on_frame(FrameDirection::Received, FrameChannel::HttpResponse, b"b");
        log.on_frame(FrameDirection::Received, FrameChannel::HttpSse, b"c");
        let events = log.snapshot();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].body, "b");
        assert_eq!(events[1].body, "c");
        assert!(events[0].seq < events[1].seq);
    }

    #[test]
    fn since_returns_only_newer_events() {
        let log = EventLog::new(10);
        for body in [b"a", b"b", b"c"] {
            log.on_frame(FrameDirection::Sent, FrameChannel::Stdio, body);
        }
        let all = log.snapshot();
        let after_first = log.since(all[0].seq);
        assert_eq!(after_first.len(), 2);
        assert_eq!(after_first[0].body, "b");
        assert!(log.since(all[2].seq).is_empty());
    }

    #[tokio::test]
    async fn subscribers_see_live_frames() {
        let log = EventLog::new(10);
        let mut rx = log.subscribe();
        log.on_frame(FrameDirection::Received, FrameChannel::HttpSse, b"live");
        let event = rx.try_recv().expect("broadcast delivered");
        assert_eq!(event.body, "live");
    }
}
