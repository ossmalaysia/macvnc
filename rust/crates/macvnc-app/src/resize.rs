//! Dynamic resolution: decides when the Mac's virtual display should follow
//! the MacVNC window. Timing follows iShareScreen's viewer: a new size must
//! hold for a moment and differ by a real amount, and requests are spaced out,
//! because each one restarts the Mac's video encoder.
use std::time::{Duration, Instant};

/// The window must keep a new size this long before it is requested.
pub const DEBOUNCE: Duration = Duration::from_millis(500);
/// Smaller changes on both axes are ignored (scrollbars, rounding jitter).
const MIN_DELTA: u32 = 32;
/// Floor between consecutive resize requests.
const MIN_INTERVAL: Duration = Duration::from_millis(2500);
/// The Mac's virtual display accepts at most this backing size; the window
/// is letterboxed beyond it.
const MAX: [u32; 2] = [3840, 2160];
const MIN: [u32; 2] = [640, 480];

/// The display size to request for a view of `px` physical pixels: even
/// (HEVC prefers even dimensions) and within what the Mac accepts.
pub fn target(px: [u32; 2]) -> [u16; 2] {
    let fit = |v: u32, i: usize| (v.clamp(MIN[i], MAX[i]) & !1) as u16;
    [fit(px[0], 0), fit(px[1], 1)]
}

#[derive(Default)]
pub struct Tracker {
    /// Window size (physical pixels) the current Mac display was sized for.
    acted_on: Option<[u32; 2]>,
    pending: Option<([u32; 2], Instant)>,
    last_request: Option<Instant>,
}
impl Tracker {
    /// Starts tracking from the window size the session connected with.
    pub fn reset(&mut self, px: [u32; 2]) {
        *self = Self {
            acted_on: Some(px),
            ..Self::default()
        };
    }
    /// True while a new size is waiting out the debounce or interval.
    pub fn waiting(&self) -> bool {
        self.pending.is_some()
    }
    /// The display size to request now, if any.
    pub fn poll(&mut self, px: [u32; 2], now: Instant) -> Option<[u16; 2]> {
        if px[0] == 0 || px[1] == 0 {
            return None; // Minimised.
        }
        let acted_on = *self.acted_on.get_or_insert(px);
        let moved = |i: usize| px[i].abs_diff(acted_on[i]) >= MIN_DELTA;
        if !(moved(0) || moved(1)) {
            self.pending = None;
            return None;
        }
        match self.pending {
            Some((size, _)) if size == px => {}
            _ => self.pending = Some((px, now)),
        }
        let (_, since) = self.pending?;
        let settled = now.duration_since(since) >= DEBOUNCE;
        let spaced = self
            .last_request
            .is_none_or(|last| now.duration_since(last) >= MIN_INTERVAL);
        if !(settled && spaced) {
            return None;
        }
        // Track the window size acted on, not the clamped request, so an
        // oversized but stable window does not re-request forever.
        self.acted_on = Some(px);
        self.pending = None;
        self.last_request = Some(now);
        Some(target(px))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_is_even_and_within_mac_limits() {
        assert_eq!(target([1533, 871]), [1532, 870]);
        assert_eq!(target([5120, 2880]), [3840, 2160]);
        assert_eq!(target([300, 200]), [640, 480]);
    }

    #[test]
    fn requests_only_after_the_size_settles() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        t.reset([1920, 1080]);
        assert_eq!(t.poll([1920, 1080], t0), None);
        // Dragging through sizes keeps restarting the debounce.
        assert_eq!(t.poll([1700, 1000], t0), None);
        assert!(t.waiting());
        assert_eq!(t.poll([1600, 950], t0 + Duration::from_millis(400)), None);
        assert_eq!(t.poll([1600, 950], t0 + Duration::from_millis(800)), None);
        assert_eq!(
            t.poll([1600, 950], t0 + Duration::from_millis(900)),
            Some([1600, 950])
        );
        assert!(!t.waiting());
        assert_eq!(t.poll([1600, 950], t0 + Duration::from_secs(5)), None);
    }

    #[test]
    fn ignores_jitter_and_spaces_requests() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        t.reset([1600, 900]);
        assert_eq!(t.poll([1620, 910], t0 + Duration::from_secs(1)), None);
        assert!(!t.waiting(), "below the delta threshold");
        assert_eq!(t.poll([1200, 800], t0), None);
        let first = t0 + DEBOUNCE;
        assert_eq!(t.poll([1200, 800], first), Some([1200, 800]));
        // A second change settles quickly but must wait out the interval.
        assert_eq!(t.poll([1800, 1000], first), None);
        assert_eq!(t.poll([1800, 1000], first + Duration::from_secs(1)), None);
        assert_eq!(
            t.poll([1800, 1000], first + Duration::from_millis(2500)),
            Some([1800, 1000])
        );
    }

    #[test]
    fn oversized_stable_window_requests_once() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        t.reset([1920, 1080]);
        t.poll([5120, 2880], t0);
        assert_eq!(t.poll([5120, 2880], t0 + DEBOUNCE), Some([3840, 2160]));
        assert_eq!(t.poll([5120, 2880], t0 + Duration::from_secs(10)), None);
    }

    #[test]
    fn minimised_window_never_requests() {
        let mut t = Tracker::default();
        t.reset([1920, 1080]);
        let t0 = Instant::now();
        assert_eq!(t.poll([0, 0], t0), None);
        assert_eq!(t.poll([0, 0], t0 + Duration::from_secs(5)), None);
    }
}
