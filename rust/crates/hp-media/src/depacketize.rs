use crate::RtpPacket;
use std::collections::{BTreeMap, HashMap, VecDeque};

const MAX_GROUPS: usize = 64;
const MAX_GROUP_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;
const HOLD_MS: u64 = 25;
const INCOMPLETE_IDLE_MS: u64 = 200;
const MAX_GROUP_AGE_MS: u64 = 1000;
const MAX_CANDIDATE_PACKETS: usize = 8;
const MAX_CANDIDATE_BYTES: usize = 64 * 1024;
#[derive(Clone)]
pub struct AccessUnit {
    pub generation: u64,
    pub loss_epoch: u64,
    pub data: Vec<u8>,
    pub tile: usize,
    pub pts: i64,
    pub rtp_timestamp: u32,
    pub donl: u16,
    pub key: bool,
}
struct Group {
    packets: HashMap<u16, RtpPacket>,
    first: u64,
    order: u64,
    bytes: usize,
    marker: Option<u16>,
    marker_at: Option<u64>,
    last_packet: u64,
}
#[derive(Default)]
struct SourceObservation {
    packets: u64,
    last: u64,
    donl: Option<bool>,
    params: Vec<Vec<u8>>,
    prefix: VecDeque<RtpPacket>,
    prefix_bytes: usize,
}
pub struct Depacketizer {
    tiles: usize,
    sources: Vec<u32>,
    groups: HashMap<(u32, u32), Group>,
    first: Option<u64>,
    next_pts: i64,
    have_key: bool,
    params: BTreeMap<Vec<u8>, Vec<u8>>,
    pub dropped: u64,
    last_ts: HashMap<u32, u32>,
    next_group: u64,
    counters: BTreeMap<&'static str, u64>,
    nal_types: [u64; 64],
    observed: BTreeMap<u32, SourceObservation>,
    generation: u64,
    loss_epoch: u64,
}
impl Depacketizer {
    pub fn new(tile_count: usize) -> Self {
        Self {
            tiles: tile_count.clamp(1, 16),
            sources: vec![],
            groups: HashMap::new(),
            first: None,
            next_pts: 0,
            have_key: false,
            params: BTreeMap::new(),
            dropped: 0,
            last_ts: HashMap::new(),
            next_group: 0,
            counters: BTreeMap::new(),
            nal_types: [0; 64],
            observed: BTreeMap::new(),
            generation: 0,
            loss_epoch: 0,
        }
    }
    pub fn sources(&self) -> &[u32] {
        &self.sources
    }
    pub fn loss_epoch(&self) -> u64 {
        self.loss_epoch
    }
    fn record_loss(&mut self, reason: &'static str) {
        self.dropped += 1;
        self.loss_epoch = self.loss_epoch.saturating_add(1);
        self.count(reason);
    }
    fn count(&mut self, name: &'static str) {
        *self.counters.entry(name).or_default() += 1;
    }
    pub fn diagnostics(&self) -> String {
        let hist: Vec<_> = self
            .nal_types
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(k, n)| format!("{k}:{n}"))
            .collect();
        let sources: Vec<_> = self
            .observed
            .iter()
            .map(|(id, s)| {
                format!(
                    "{id}:{}:{}",
                    s.packets,
                    match s.donl {
                        Some(true) => "DONL",
                        Some(false) => "standard",
                        None => "unknown",
                    }
                )
            })
            .collect();
        format!("sources={}/{} pending={} params={} have_key={} emitted={} dropped={} counters={:?} nal_types=[{}] observed=[{}]",self.sources.len(),self.tiles,self.groups.len(),self.params.len(),self.have_key,self.next_pts,self.dropped,self.counters,hist.join(","),sources.join(","))
    }
    pub fn push(&mut self, p: RtpPacket, now: u64) -> Vec<AccessUnit> {
        self.count("packets");
        if p.marker {
            self.count("markers");
        }
        if p.payload.first() == Some(&0x92) {
            self.count("avc_config_marker");
        }
        if p.payload.first().is_some_and(|b| b & 31 == 28) {
            self.count("avc_fu_a_header");
        }
        if p.payload.len() >= 2 {
            let kind = (p.payload[0] >> 1 & 63) as usize;
            self.nal_types[kind] += 1;
            if kind == 49 && p.payload.len() >= 3 {
                if p.payload[2] & 128 != 0 {
                    self.count("fu_start");
                }
                if p.payload[2] & 64 != 0 {
                    self.count("fu_end");
                }
            }
        }
        // The payload type is dynamically negotiated; this receiver is attached
        // exclusively to the authenticated video socket, not the audio socket.
        if p.payload.len() < 2 {
            self.count("short");
            return self.poll(now);
        }
        // Infer optional DONL only from a fully validated parameter-set AP.
        // Single-picture HEVC can use standard RFC7798 framing, unlike Apple's
        // tiled stream. Never infer it from arbitrary compressed slice bytes.
        if self.observed.contains_key(&p.ssrc) || self.observed.len() < 32 {
            let s = self.observed.entry(p.ssrc).or_default();
            s.packets += 1;
            s.last = now;
            if p.payload[0] >> 1 & 63 == 48 {
                let apple = parse_parameter_ap(&p.payload, 4);
                let standard = parse_parameter_ap(&p.payload, 2);
                match (apple, standard) {
                    (Some(params), None) => {
                        s.donl = Some(true);
                        s.params = params;
                    }
                    (None, Some(params)) => {
                        s.donl = Some(false);
                        s.params = params;
                    }
                    _ => (),
                }
            }
        }
        if !self.sources.contains(&p.ssrc) {
            if self.sources.len() >= self.tiles {
                let replace = self.tiles == 1
                    && self
                        .observed
                        .get(&self.sources[0])
                        .is_some_and(|s| now.saturating_sub(s.last) >= 100)
                    && self.observed.get(&p.ssrc).is_some_and(|s| s.packets >= 8);
                if replace {
                    self.generation = self.generation.saturating_add(1);
                    self.sources.clear();
                    self.groups.clear();
                    self.params.clear();
                    self.have_key = false;
                    self.last_ts.clear();
                    self.dropped += 1;
                    self.count("source_handoff");
                } else {
                    self.count("unknown_source");
                    // Adoption requires evidence from several packets. Preserve
                    // their FU start/configuration instead of losing the first
                    // independently decodable picture of the new generation.
                    // Observations are capped at32 sources; each queue is also
                    // bounded independently of the active assembly budget.
                    if self.tiles == 1 && p.payload.len() <= MAX_CANDIDATE_BYTES {
                        if let Some(s) = self.observed.get_mut(&p.ssrc) {
                            while s.prefix.len() >= MAX_CANDIDATE_PACKETS
                                || s.prefix_bytes + p.payload.len() > MAX_CANDIDATE_BYTES
                            {
                                if let Some(old) = s.prefix.pop_front() {
                                    s.prefix_bytes -= old.payload.len();
                                }
                            }
                            s.prefix_bytes += p.payload.len();
                            s.prefix.push_back(p);
                        }
                    }
                    return self.poll(now);
                }
            }
            self.sources.push(p.ssrc);
            self.sources.sort_unstable();
        }
        let mut out = Vec::new();
        if let Some(s) = self.observed.get_mut(&p.ssrc) {
            let prefix = std::mem::take(&mut s.prefix);
            s.prefix_bytes = 0;
            // Begin the normal reordering grace period at adoption: these
            // packets could not enter assembly while their source was unknown.
            for prior in prefix {
                out.extend(self.push_selected(prior, now));
            }
        }
        out.extend(self.push_selected(p, now));
        out
    }
    fn push_selected(&mut self, p: RtpPacket, now: u64) -> Vec<AccessUnit> {
        if let Some(s) = self.observed.get(&p.ssrc) {
            for nal in &s.params {
                if self.params.len() < 64 {
                    self.params.insert(nal.clone(), nal.clone());
                }
            }
        }
        self.first.get_or_insert(now);
        let key = (p.ssrc, p.timestamp);
        if self
            .groups
            .get(&key)
            .is_none_or(|g| !g.packets.contains_key(&p.seq))
        {
            let pending_bytes: usize = self.groups.values().map(|g| g.bytes).sum();
            if p.payload.len() > MAX_GROUP_BYTES
                || pending_bytes.saturating_add(p.payload.len()) > MAX_PENDING_BYTES
            {
                // Keep the existing bounded groups intact; accepting a new
                // datagram must not multiply the 8MiB per-AU cap by64 groups.
                self.record_loss("pending_byte_limit");
                return self.poll(now);
            }
        }
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            if let Some(old) = self
                .groups
                .iter()
                .min_by_key(|(_, g)| g.first)
                .map(|(k, _)| *k)
            {
                self.groups.remove(&old);
                self.record_loss("group_limit");
            }
        }
        let order = self.next_group;
        self.next_group += 1;
        let g = self.groups.entry(key).or_insert(Group {
            packets: HashMap::new(),
            first: now,
            order,
            bytes: 0,
            marker: None,
            marker_at: None,
            last_packet: now,
        });
        if !g.packets.contains_key(&p.seq) {
            g.bytes += p.payload.len();
            if p.marker {
                g.marker = Some(p.seq);
                g.marker_at.get_or_insert(now);
            }
            g.last_packet = now;
            g.packets.insert(p.seq, p);
        }
        if g.bytes > MAX_GROUP_BYTES || g.packets.len() > 8192 {
            self.groups.remove(&key);
            self.record_loss("byte_limit");
        }
        self.poll(now)
    }
    pub fn poll(&mut self, now: u64) -> Vec<AccessUnit> {
        // Discover the complete SSRC set before assigning immutable tile indices.
        if self.sources.len() < self.tiles && now.saturating_sub(self.first.unwrap_or(now)) < 750 {
            return vec![];
        }
        let mut keys: Vec<_> = self.groups.keys().copied().collect();
        // RTP timestamp origins and DONL counters are independent per SSRC.
        // Preserve cross-source receive order (the reference session's actual
        // feed behavior), never sort/drop one source against another's clock.
        keys.sort_by_key(|key| self.groups[key].order);
        let mut out = vec![];
        for key in keys {
            let g = &self.groups[&key];
            if self
                .last_ts
                .get(&key.0)
                .is_some_and(|ts| (key.1.wrapping_sub(*ts) as i32) <= 0)
            {
                self.groups.remove(&key);
                self.dropped += 1;
                self.count("late_timestamp");
                continue;
            }
            // A marker can precede an earlier FU fragment after an arbitrarily
            // long burst. Its own arrival starts the repair window; measuring
            // from the group's first packet falsely classified such reorder.
            if let Some(at) = g.marker_at {
                if now.saturating_sub(at) < HOLD_MS {
                    break;
                }
            } else if now.saturating_sub(g.last_packet) < INCOMPLETE_IDLE_MS
                && now.saturating_sub(g.first) < MAX_GROUP_AGE_MS
            {
                break;
            }
            let g = self.groups.remove(&key).unwrap();
            if g.marker.is_none() {
                self.record_loss("missing_marker");
                continue;
            }
            let end = g.marker.unwrap();
            let mut packets: Vec<_> = g.packets.into_values().collect();
            packets.sort_by_key(|p| std::cmp::Reverse(end.wrapping_sub(p.seq)));
            if packets
                .windows(2)
                .any(|w| w[1].seq != w[0].seq.wrapping_add(1))
            {
                self.record_loss("sequence_gap");
                continue;
            }
            let apple_donl = self
                .observed
                .get(&key.0)
                .and_then(|s| s.donl)
                .unwrap_or(true);
            let (nals, donl) = match reassemble(&packets, apple_donl) {
                Ok(v) => v,
                Err(reason) => {
                    self.record_loss(reason);
                    continue;
                }
            };
            let mut data = vec![];
            let mut keyframe = false;
            let mut vcl = false;
            let mut first_slice = false;
            for nal in nals {
                let kind = nal[0] >> 1 & 63;
                if (32..=34).contains(&kind) {
                    if self.params.len() < 64 && nal.len() <= 65536 {
                        self.params.insert(nal.clone(), nal);
                    }
                    continue;
                }
                if kind > 31 || nal.len() < 3 {
                    continue;
                }
                // first_slice_segment_in_pic_flag marks the first slice of a
                // picture, not whether a VCL NAL is decodable. All following
                // slices belong in the same AU; dropping them conceals bands.
                first_slice |= nal[2] & 128 != 0;
                if nal[2] & 128 == 0 {
                    self.count("continuation_slices");
                }
                keyframe |= (16..=21).contains(&kind);
                vcl = true;
                data.extend_from_slice(&[0, 0, 0, 1]);
                data.extend(nal);
            }
            if !vcl {
                self.count("no_vcl");
                continue;
            }
            if !first_slice {
                self.record_loss("missing_first_slice");
                continue;
            }
            if !self.have_key && !keyframe {
                self.count("pre_key");
                continue;
            }
            if keyframe {
                self.count("keyframes");
                self.have_key = true;
                let mut pref = vec![];
                for kind in 32..=34 {
                    for nal in self.params.values().filter(|n| n[0] >> 1 & 63 == kind) {
                        pref.extend_from_slice(&[0, 0, 0, 1]);
                        pref.extend(nal);
                    }
                }
                pref.extend(data);
                data = pref;
            }
            let tile = self.sources.binary_search(&key.0).unwrap();
            out.push(AccessUnit {
                generation: self.generation,
                loss_epoch: self.loss_epoch,
                data,
                tile,
                pts: self.next_pts,
                rtp_timestamp: key.1,
                donl,
                key: keyframe,
            });
            self.next_pts += 1;
            self.last_ts.insert(key.0, key.1);
        }
        out
    }
}
fn parse_parameter_ap(b: &[u8], mut offset: usize) -> Option<Vec<Vec<u8>>> {
    let mut params = vec![];
    while offset < b.len() {
        let size = u16::from_be_bytes(b.get(offset..offset + 2)?.try_into().ok()?) as usize;
        offset += 2;
        if size < 2 {
            return None;
        }
        let nal = b.get(offset..offset + size)?;
        offset += size;
        if nal[0] & 128 != 0 || nal[1] & 7 == 0 {
            return None;
        }
        if (32..=34).contains(&(nal[0] >> 1 & 63)) {
            if size > 65536 || params.len() >= 64 {
                return None;
            }
            params.push(nal.to_vec());
        }
    }
    (!params.is_empty()).then_some(params)
}
fn reassemble(
    packets: &[RtpPacket],
    apple_donl: bool,
) -> Result<(Vec<Vec<u8>>, u16), &'static str> {
    let mut nals = vec![];
    let mut fragment: Option<Vec<u8>> = None;
    let mut fragment_donl = 0;
    let mut first = None;
    for p in packets {
        let b = &p.payload;
        if b.len() < 2 {
            return Err("reassemble_short");
        }
        let kind = b[0] >> 1 & 63;
        let o = if kind == 49 { 3 } else { 2 };
        if apple_donl && b.len() < o + 2 {
            return Err("donl_short");
        }
        let donl = if apple_donl {
            u16::from_be_bytes([b[o], b[o + 1]])
        } else {
            0
        };
        first.get_or_insert(donl);
        match kind {
            48 => {
                if fragment.is_some() {
                    return Err("ap_during_fu");
                }
                let mut o = if apple_donl { 4 } else { 2 };
                while o < b.len() {
                    if o + 2 > b.len() {
                        return Err("ap_size_short");
                    }
                    let n = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
                    o += 2;
                    if n < 2 || o + n > b.len() {
                        return Err("ap_size_invalid");
                    }
                    nals.push(b[o..o + n].to_vec());
                    o += n;
                }
            }
            49 => {
                let payload_start = if apple_donl { 5 } else { 3 };
                if b.len() <= payload_start {
                    return Err("fu_short");
                }
                let start = b[2] & 128 != 0;
                let end = b[2] & 64 != 0;
                if start {
                    if fragment.is_some() {
                        return Err("fu_restarted");
                    }
                    fragment = Some(vec![(b[0] & 129) | ((b[2] & 63) << 1), b[1]]);
                    fragment_donl = donl;
                }
                if fragment_donl != donl {
                    return Err("fu_donl_changed");
                }
                fragment
                    .as_mut()
                    .ok_or("fu_missing_start")?
                    .extend_from_slice(&b[payload_start..]);
                if end {
                    nals.push(fragment.take().ok_or("fu_missing_start")?);
                }
            }
            _ => {
                if fragment.is_some() {
                    return Err("single_during_fu");
                }
                let mut n = b[..2].to_vec();
                n.extend_from_slice(&b[if apple_donl { 4 } else { 2 }..]);
                nals.push(n);
            }
        }
    }
    if fragment.is_some() {
        return Err("fu_missing_end");
    }
    Ok((nals, first.ok_or("empty_group")?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_pending_memory_is_capped_independently_of_group_count() {
        let mut d = Depacketizer::new(1);
        for i in 0..4 {
            let mut payload = vec![0; MAX_GROUP_BYTES];
            payload[..2].copy_from_slice(&[2, 1]);
            let mut packet = p(i, payload, false);
            packet.timestamp = i as u32;
            d.push(packet, 0);
        }
        assert_eq!(
            d.groups.values().map(|g| g.bytes).sum::<usize>(),
            MAX_PENDING_BYTES
        );
        let mut extra = p(9, vec![2, 1, 0, 0, 128], false);
        extra.timestamp = 9;
        d.push(extra, 0);
        assert_eq!(d.groups.len(), 4);
        assert_eq!(d.counters.get("pending_byte_limit"), Some(&1));
        assert_eq!(d.loss_epoch(), 1);
    }
    fn p(seq: u16, body: Vec<u8>, marker: bool) -> RtpPacket {
        RtpPacket {
            ssrc: 1,
            seq,
            timestamp: 2,
            marker,
            pt: 96,
            payload: body,
        }
    }
    #[test]
    fn standard_hevc_framing_is_selected_from_valid_parameter_ap() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![96, 1, 0, 3, 66, 1, 128], true), 0);
        let mut a = p(2, vec![98, 1, 0x93, 128, 7], false);
        a.timestamp = 3;
        d.push(a, 1);
        let mut b = p(3, vec![98, 1, 0x53, 9], true);
        b.timestamp = 3;
        d.push(b, 2);
        let out = d.poll(30);
        assert_eq!(out.len(), 1);
        assert!(out[0].data.ends_with(&[0, 0, 0, 1, 38, 1, 128, 7, 9]));
        assert!(d.diagnostics().contains("standard"));
    }
    #[test]
    fn source_handoff_preserves_first_fragmented_keyframe() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![38, 1, 0, 0, 128], true), 0);
        d.poll(30);
        // The parameter AP and FU start arrive before the eight-packet
        // adoption threshold. All fragments belong to the first new picture.
        for seq in 1..=8 {
            let body = match seq {
                1 => vec![96, 1, 0, 3, 66, 1, 128],
                2 => vec![98, 1, 0x93, 128, 2],
                8 => vec![98, 1, 0x53, 8],
                _ => vec![98, 1, 0x13, seq as u8],
            };
            let mut q = p(seq, body, seq == 8);
            q.ssrc = 2;
            assert!(d.push(q, 110 + seq as u64).is_empty());
        }
        let out = d.poll(150);
        assert_eq!(out.len(), 1);
        assert!(out[0].key);
        assert_eq!(out[0].generation, 1);
        assert!(out[0]
            .data
            .ends_with(&[0, 0, 0, 1, 38, 1, 128, 2, 3, 4, 5, 6, 7, 8]));
        assert!(!d.counters.contains_key("fu_missing_start"));
        assert_eq!(d.observed[&2].packets, 8); // replay does not double-count
        assert!(d.observed[&2].prefix.is_empty());
    }
    #[test]
    fn candidate_prefix_is_bounded_by_bytes_and_packet_count() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![38, 1, 0, 0, 128], true), 0);
        for seq in 1..=20 {
            let mut q = p(seq, vec![2; 10_000], false);
            q.ssrc = 2;
            d.push(q, 1);
        }
        assert_eq!(d.observed[&2].prefix.len(), 6);
        assert_eq!(d.observed[&2].prefix_bytes, 60_000);
        for seq in 21..=40 {
            let mut q = p(seq, vec![2, 1], false);
            q.ssrc = 2;
            d.push(q, 2);
        }
        assert_eq!(d.observed[&2].prefix.len(), MAX_CANDIDATE_PACKETS);
        assert_eq!(d.observed[&2].prefix_bytes, 16);
        assert_eq!(d.sources(), &[1]);
    }
    #[test]
    fn single_picture_adopts_new_source_only_after_old_source_quiet() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![38, 1, 0, 0, 128], true), 0);
        for i in 1..=8 {
            let mut q = p(i, vec![96, 1, 0, 3, 66, 1, 128], true);
            q.ssrc = 2;
            q.timestamp = i as u32;
            d.push(q, i as u64 * 10);
        }
        assert_eq!(d.sources(), &[1]);
        let mut q = p(9, vec![96, 1, 0, 3, 66, 1, 128], true);
        q.ssrc = 2;
        q.timestamp = 9;
        d.push(q, 110);
        assert_eq!(d.sources(), &[2]);
        assert_eq!(d.counters.get("source_handoff"), Some(&1));
        assert!(d.dropped > 0);
        let mut q = p(10, vec![38, 1, 128, 7], true);
        q.ssrc = 2;
        q.timestamp = 10;
        d.push(q, 111);
        assert_eq!(d.poll(140).len(), 1);
    }
    #[test]
    fn fu_rollover_out_of_order() {
        let mut d = Depacketizer::new(1);
        d.push(p(0, vec![98, 1, 0x53, 0, 5, 8], true), 0);
        d.push(p(65535, vec![98, 1, 0x93, 0, 5, 128, 7], false), 1);
        let a = d.poll(30);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].data, vec![0, 0, 0, 1, 38, 1, 128, 7, 8]);
    }
    #[test]
    fn fu_missing_packet_is_discarded() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![98, 1, 0x93, 0, 5, 128], false), 0);
        d.push(p(3, vec![98, 1, 0x53, 0, 5, 8], true), 1);
        assert!(d.poll(30).is_empty());
        assert_eq!(d.dropped, 1);
    }
    #[test]
    fn marker_before_start_waits() {
        let mut d = Depacketizer::new(1);
        assert!(d.push(p(2, vec![98, 1, 0x53, 0, 5, 8], true), 0).is_empty());
        assert!(d.poll(10).is_empty());
    }
    #[test]
    fn reorder_window_starts_at_marker_even_after_long_burst() {
        let mut d = Depacketizer::new(1);
        d.push(p(3, vec![98, 1, 0x13, 0, 5, 8], false), 0);
        assert!(d
            .push(p(4, vec![98, 1, 0x53, 0, 5, 9], true), 40)
            .is_empty());
        assert!(d
            .push(p(2, vec![98, 1, 0x93, 0, 5, 128, 7], false), 50)
            .is_empty());
        assert!(d.poll(64).is_empty());
        let out = d.poll(65);
        assert_eq!(out.len(), 1);
        assert_eq!(d.loss_epoch(), 0);
        assert!(out[0].data.ends_with(&[38, 1, 128, 7, 8, 9]));
    }
    #[test]
    fn loss_epochs_preserve_drop_order_and_ignore_provably_stale_orphans() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![38, 1, 0, 0, 128], true), 0);
        let mut orphan = p(2, vec![98, 1, 0x53, 0, 0, 7], true);
        orphan.timestamp = 3;
        d.push(orphan, 0);
        let out = d.poll(30);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].loss_epoch, 0);
        assert_eq!(d.loss_epoch(), 1);
        let mut key = p(3, vec![38, 1, 0, 0, 128], true);
        key.timestamp = 4;
        d.push(key, 40);
        assert_eq!(d.poll(70)[0].loss_epoch, 1);
        let mut late = p(9, vec![98, 1, 0x53, 0, 0, 7], false);
        late.timestamp = 3;
        d.push(late, 80);
        assert_eq!(d.loss_epoch(), 1);
        assert_eq!(d.counters.get("late_timestamp"), Some(&1));
    }
    #[test]
    fn incomplete_group_lifetime_is_bounded_even_with_trickled_fragments() {
        let mut d = Depacketizer::new(1);
        d.push(p(1, vec![98, 1, 0x93, 0, 0, 128], false), 0);
        for i in 1..=6 {
            d.push(p(i + 1, vec![98, 1, 0x13, 0, 0, 8], false), i as u64 * 150);
        }
        assert_eq!(d.loss_epoch(), 0);
        d.poll(1000);
        assert_eq!(d.loss_epoch(), 1);
        assert_eq!(d.counters.get("missing_marker"), Some(&1));
    }
    #[test]
    fn unknown_sources_bounded() {
        let mut d = Depacketizer::new(1);
        for n in 0..100 {
            let mut q = p(1, vec![38, 1, 0, 0, 128], true);
            q.ssrc = n;
            d.push(q, 0);
        }
        assert_eq!(d.sources.len(), 1);
    }
    #[test]
    fn ap_no_dond() {
        let q = p(
            1,
            vec![96, 1, 0, 7, 0, 3, 38, 1, 128, 0, 3, 2, 1, 128],
            true,
        );
        let (n, donl) = reassemble(&[q], true).unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(donl, 7);
    }
    #[test]
    fn independent_source_clocks_preserve_arrival_and_global_key_gate() {
        let mut d = Depacketizer::new(2);
        let mut key = p(8, vec![38, 1, 0, 6, 128, 88], true);
        key.ssrc = 10;
        key.timestamp = 1_000_000;
        d.push(key, 0);
        let mut delta = p(9, vec![2, 1, 0, 7, 128, 99], true);
        delta.ssrc = 20;
        delta.timestamp = 10;
        d.push(delta, 1);
        let out = d.poll(30);
        assert_eq!(out.len(), 2);
        assert!(out[0].key);
        assert_eq!(out[0].tile, 0);
        assert!(!out[1].key);
        assert_eq!(out[1].tile, 1);
        assert_eq!(out[1].pts, out[0].pts + 1);
        let mut next = p(10, vec![2, 1, 0, 8, 128, 99], true);
        next.ssrc = 20;
        next.timestamp = 11;
        d.push(next, 40);
        assert_eq!(d.poll(70).len(), 1);
    }
}
