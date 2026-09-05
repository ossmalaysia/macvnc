use aes::Aes256;
use anyhow::{bail, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
type Cipher = ctr::Ctr128BE<Aes256>;
type Auth = Hmac<Sha1>;

#[derive(Zeroize, ZeroizeOnDrop)]
struct Keys {
    cipher: [u8; 32],
    auth: [u8; 20],
    salt: [u8; 14],
}
fn derive(blob: &[u8], label: u8) -> Result<Keys> {
    if blob.len() != 46 {
        bail!("SRTP key must contain 46 bytes")
    }
    fn kdf(blob: &[u8], label: u8, out: &mut [u8]) {
        let mut iv = [0; 16];
        iv[..14].copy_from_slice(&blob[32..]);
        iv[7] ^= label;
        Cipher::new_from_slices(&blob[..32], &iv)
            .unwrap()
            .apply_keystream(out);
    }
    let mut k = Keys {
        cipher: [0; 32],
        auth: [0; 20],
        salt: [0; 14],
    };
    kdf(blob, label, &mut k.cipher);
    kdf(blob, label + 1, &mut k.auth);
    kdf(blob, label + 2, &mut k.salt);
    Ok(k)
}
fn crypt(k: &Keys, ssrc: u32, index: u64, bytes: &mut [u8]) {
    let mut iv = [0; 16];
    iv[..14].copy_from_slice(&k.salt);
    for (a, b) in iv[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
        *a ^= b;
    }
    let v = index.to_be_bytes();
    for (a, b) in iv[6..14].iter_mut().zip(v) {
        *a ^= b;
    }
    Cipher::new_from_slices(&k.cipher, &iv)
        .unwrap()
        .apply_keystream(bytes);
}
pub fn is_rtcp(p: &[u8]) -> bool {
    p.len() > 1 && (64..=95).contains(&(p[1] & 127))
}
#[derive(Clone)]
pub struct RtpPacket {
    pub ssrc: u32,
    pub seq: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub pt: u8,
    pub payload: Vec<u8>,
}
struct ReceiveState {
    highest: u64,
    seen: u128,
}
pub struct SrtpReceiver {
    keys: Keys,
    states: HashMap<u32, ReceiveState>,
}
impl SrtpReceiver {
    pub fn new(blob: &[u8]) -> Result<Self> {
        Ok(Self {
            keys: derive(blob, 0)?,
            states: HashMap::new(),
        })
    }
    pub fn sources(&self) -> Vec<u32> {
        let mut v: Vec<_> = self.states.keys().copied().collect();
        v.sort_unstable();
        v
    }
    pub fn highest_sequence(&self, ssrc: u32) -> u32 {
        self.states.get(&ssrc).map_or(0, |s| s.highest as u32)
    }
    pub fn unprotect(&mut self, p: &[u8]) -> Result<Option<RtpPacket>> {
        if p.len() < 22 || p.len() > 65535 || p[0] >> 6 != 2 || is_rtcp(p) {
            return Ok(None);
        }
        let len = p.len() - 10;
        let seq = u16::from_be_bytes([p[2], p[3]]);
        let ssrc = u32::from_be_bytes(p[8..12].try_into().unwrap());
        let previous = self.states.get(&ssrc).map(|s| s.highest);
        let roc = previous.map_or(0, |v| v >> 16);
        let guess = previous.map_or(0, |v| {
            let delta = seq as i32 - (v as u16) as i32;
            if delta < -32768 {
                roc + 1
            } else if delta > 32768 {
                roc.saturating_sub(1)
            } else {
                roc
            }
        });
        if guess > u32::MAX as u64 {
            return Ok(None);
        }
        let index = (guess << 16) | seq as u64;
        if let Some(s) = self.states.get(&ssrc) {
            if index <= s.highest {
                let age = s.highest - index;
                if age >= 128 || s.seen & (1u128 << age) != 0 {
                    return Ok(None);
                }
            }
        }
        let mut h = Auth::new_from_slice(&self.keys.auth).unwrap();
        h.update(&p[..len]);
        h.update(&(guess as u32).to_be_bytes());
        if !bool::from(h.finalize().into_bytes()[..10].ct_eq(&p[len..])) {
            return Ok(None);
        }
        let mut off = 12 + (p[0] as usize & 15) * 4;
        if p[0] & 16 != 0 {
            if off + 4 > len {
                return Ok(None);
            }
            off += 4 + u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize * 4;
        }
        if off > len {
            return Ok(None);
        }
        let mut payload = p[off..len].to_vec();
        crypt(&self.keys, ssrc, index, &mut payload);
        if p[0] & 32 != 0 {
            let count = payload.last().copied().unwrap_or(0) as usize;
            if count == 0 || count > payload.len() {
                return Ok(None);
            }
            payload.truncate(payload.len() - count);
        }
        if !self.states.contains_key(&ssrc) && self.states.len() >= 32 {
            return Ok(None);
        }
        let s = self.states.entry(ssrc).or_insert(ReceiveState {
            highest: index,
            seen: 0,
        });
        if index > s.highest {
            let delta = index - s.highest;
            s.seen = if delta >= 128 { 0 } else { s.seen << delta };
            s.highest = index;
        }
        s.seen |= 1u128 << (s.highest - index);
        Ok(Some(RtpPacket {
            ssrc,
            seq,
            timestamp: u32::from_be_bytes(p[4..8].try_into().unwrap()),
            marker: p[1] & 128 != 0,
            pt: p[1] & 127,
            payload,
        }))
    }
}
/// Outbound RTP protection with an owned, non-reusable packet index.
pub struct SrtpSender {
    keys: Keys,
    ssrc: u32,
    index: u64,
    heartbeat_timestamp: u32,
}
impl SrtpSender {
    pub fn new(blob: &[u8], ssrc: u32) -> Result<Self> {
        Ok(Self {
            keys: derive(blob, 0)?,
            ssrc,
            index: 0,
            heartbeat_timestamp: 0,
        })
    }
    pub fn protect(&mut self, payload: &[u8], timestamp: u32, pt: u8) -> Result<Vec<u8>> {
        if self.index >= 1u64 << 48 {
            bail!("SRTP sending key exhausted")
        }
        if pt > 127 || (64..=95).contains(&pt) || payload.len() > 65507 - 22 {
            bail!("Invalid RTP payload")
        }
        let mut out = Vec::with_capacity(22 + payload.len());
        out.extend_from_slice(&[0x80, pt]);
        out.extend_from_slice(&(self.index as u16).to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(payload);
        crypt(&self.keys, self.ssrc, self.index, &mut out[12..]);
        let mut mac = Auth::new_from_slice(&self.keys.auth).unwrap();
        mac.update(&out);
        mac.update(&((self.index >> 16) as u32).to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        self.index += 1;
        Ok(out)
    }
    /// Apple's media peer expects this encrypted audio liveness packet every
    /// 500ms even when this client does not render audio. No microphone input.
    pub fn audio_heartbeat(&mut self) -> Result<Vec<u8>> {
        let packet = self.protect(&[0, 0x68, 0x34, 0], self.heartbeat_timestamp, 101)?;
        self.heartbeat_timestamp = self.heartbeat_timestamp.wrapping_add(480);
        Ok(packet)
    }
}
pub struct SrtcpSender {
    keys: Keys,
    index: u32,
}
impl SrtcpSender {
    pub fn new(blob: &[u8]) -> Result<Self> {
        Ok(Self {
            keys: derive(blob, 3)?,
            index: 0,
        })
    }
    pub fn protect(&mut self, p: &[u8]) -> Result<Vec<u8>> {
        if p.len() < 8 || p.len() > 65535 - 14 || self.index >= 0x7fffffff {
            bail!("Invalid RTCP packet or exhausted key")
        }
        let mut out = p.to_vec();
        let ssrc = u32::from_be_bytes(p[4..8].try_into().unwrap());
        crypt(&self.keys, ssrc, self.index as u64, &mut out[8..]);
        out.extend_from_slice(&(0x80000000 | self.index).to_be_bytes());
        self.index += 1;
        let mut h = Auth::new_from_slice(&self.keys.auth).unwrap();
        h.update(&out);
        out.extend_from_slice(&h.finalize().into_bytes()[..10]);
        Ok(out)
    }
}
pub fn build_rr(sender: u32, sources: &[(u32, u32)]) -> Vec<u8> {
    let n = sources.len().min(31);
    let mut b = vec![0; 8 + n * 24];
    b[0] = 128 | n as u8;
    b[1] = 201;
    b[2..4].copy_from_slice(&(1 + n as u16 * 6).to_be_bytes());
    b[4..8].copy_from_slice(&sender.to_be_bytes());
    for (i, (ssrc, seq)) in sources[..n].iter().enumerate() {
        let o = 8 + i * 24;
        b[o..o + 4].copy_from_slice(&ssrc.to_be_bytes());
        b[o + 8..o + 12].copy_from_slice(&seq.to_be_bytes());
    }
    b
}
/// Empty RTCP Sender Report with an explicitly supplied wall clock, so the
/// protocol layer stays deterministic and the caller owns clock acquisition.
pub fn build_empty_sr(sender: u32, unix_time: std::time::Duration) -> Vec<u8> {
    let mut out = vec![0; 28];
    out[0] = 0x80;
    out[1] = 200;
    out[2..4].copy_from_slice(&6u16.to_be_bytes());
    out[4..8].copy_from_slice(&sender.to_be_bytes());
    let ntp_seconds = (unix_time.as_secs() as u32).wrapping_add(2_208_988_800);
    let ntp_fraction = (((unix_time.subsec_nanos() as u64) << 32) / 1_000_000_000) as u32;
    let rtp_timestamp = (unix_time.as_secs() as u32)
        .wrapping_mul(90_000)
        .wrapping_add((unix_time.subsec_nanos() as u64 * 90_000 / 1_000_000_000) as u32);
    out[8..12].copy_from_slice(&ntp_seconds.to_be_bytes());
    out[12..16].copy_from_slice(&ntp_fraction.to_be_bytes());
    out[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    out
}
pub fn build_fir_legacy(target: u32) -> Vec<u8> {
    let mut b = vec![128, 192, 0, 1];
    b.extend_from_slice(&target.to_be_bytes());
    b
}
/// AVPF Full Intra Request (RFC5104), used alongside Apple's legacy FIR.
pub fn build_fir(sender: u32, target: u32, sequence: u8) -> Vec<u8> {
    let mut out = vec![0; 20];
    out[..4].copy_from_slice(&[0x84, 206, 0, 4]);
    out[4..8].copy_from_slice(&sender.to_be_bytes());
    out[12..16].copy_from_slice(&target.to_be_bytes());
    out[16] = sequence;
    out
}
pub fn build_pli(sender: u32, target: u32) -> Vec<u8> {
    let mut b = vec![129, 206, 0, 2];
    b.extend_from_slice(&sender.to_be_bytes());
    b.extend_from_slice(&target.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_datagrams_are_rejected_without_receive_state() {
        let mut r = SrtpReceiver::new(&[9; 46]).unwrap();
        let mut bytes = vec![0; 65536];
        bytes[0] = 0x80;
        bytes[1] = 96;
        assert!(r.unprotect(&bytes).unwrap().is_none());
        assert!(r.sources().is_empty());
        assert!(SrtcpSender::new(&[9; 46]).unwrap().protect(&bytes).is_err());
    }
    #[test]
    fn avpf_fir_wire_fields_and_reserved_bytes() {
        assert_eq!(
            build_fir(0x12345678, 0xabcdef01, 255),
            vec![
                0x84, 206, 0, 4, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 1, 255, 0,
                0, 0
            ]
        );
    }
    #[test]
    fn sender_report_wire_clock_fraction_and_wraparound() {
        let packet = build_empty_sr(0x12345678, std::time::Duration::new(1, 500_000_000));
        assert_eq!(
            packet,
            vec![
                0x80, 200, 0, 6, 0x12, 0x34, 0x56, 0x78, 0x83, 0xaa, 0x7e, 0x81, 0x80, 0, 0, 0, 0,
                2, 0x0f, 0x58, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let packet = build_empty_sr(0, std::time::Duration::from_secs(1u64 << 32));
        assert_eq!(&packet[8..12], &2_208_988_800u32.to_be_bytes());
        assert_eq!(&packet[16..20], &[0, 0, 0, 0]);
    }
    #[test]
    fn audio_heartbeat_matches_independent_node_crypto_and_advances() {
        let mut sender = SrtpSender::new(&[9; 46], 7).unwrap();
        let first = sender.audio_heartbeat().unwrap();
        let hex = first.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex, "806500000000000000000007d3b159bf7e7f20d10252bd2869e6");
        let mut receiver = SrtpReceiver::new(&[9; 46]).unwrap();
        let a = receiver.unprotect(&first).unwrap().unwrap();
        assert_eq!((a.seq, a.timestamp, a.pt, a.ssrc), (0, 0, 101, 7));
        assert_eq!(a.payload, [0, 0x68, 0x34, 0]);
        let b = receiver
            .unprotect(&sender.audio_heartbeat().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!((b.seq, b.timestamp), (1, 480));
    }
    #[test]
    fn sender_rollover_and_key_exhaustion_never_reuse_index() {
        let mut sender = SrtpSender::new(&[9; 46], 7).unwrap();
        sender.index = 65535;
        let mut receiver = SrtpReceiver::new(&[9; 46]).unwrap();
        assert_eq!(
            receiver
                .unprotect(&sender.audio_heartbeat().unwrap())
                .unwrap()
                .unwrap()
                .seq,
            65535
        );
        assert_eq!(
            receiver
                .unprotect(&sender.audio_heartbeat().unwrap())
                .unwrap()
                .unwrap()
                .seq,
            0
        );
        sender.index = (1u64 << 48) - 1;
        assert!(sender.audio_heartbeat().is_ok());
        assert!(sender.audio_heartbeat().is_err());
    }
    fn packet(keys: &Keys, seq: u16, roc: u32, padding: bool) -> Vec<u8> {
        let mut p = vec![
            if padding { 160 } else { 128 },
            96,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            7,
        ];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        let mut body = if padding {
            vec![4, 5, 0, 2]
        } else {
            vec![4, 5]
        };
        crypt(keys, 7, ((roc as u64) << 16) | seq as u64, &mut body);
        p.extend(body);
        let mut h = Auth::new_from_slice(&keys.auth).unwrap();
        h.update(&p);
        h.update(&roc.to_be_bytes());
        p.extend_from_slice(&h.finalize().into_bytes()[..10]);
        p
    }
    #[test]
    fn roundtrip_replay_tampering_and_rollover() {
        let blob = [9; 46];
        let k = derive(&blob, 0).unwrap();
        let mut r = SrtpReceiver::new(&blob).unwrap();
        let a = packet(&k, 65535, 0, true);
        assert_eq!(r.unprotect(&a).unwrap().unwrap().payload, vec![4, 5]);
        assert!(r.unprotect(&a).unwrap().is_none());
        let b = packet(&k, 0, 1, false);
        assert!(r.unprotect(&b).unwrap().is_some());
        let c = packet(&k, 65534, 0, false);
        assert!(r.unprotect(&c).unwrap().is_some());
        let mut d = packet(&k, 1, 1, false);
        d[15] ^= 1;
        assert!(r.unprotect(&d).unwrap().is_none());
    }
    #[test]
    fn short_and_wrong_version() {
        let mut r = SrtpReceiver::new(&[0; 46]).unwrap();
        for n in 0..30 {
            assert!(r.unprotect(&vec![0; n]).unwrap().is_none());
        }
        assert!(SrtpReceiver::new(&[0; 45]).is_err());
    }
    #[test]
    fn rtcp_layout() {
        assert_eq!(build_rr(7, &[(3, 65536)]).len(), 32);
        let mut s = SrtcpSender::new(&[0; 46]).unwrap();
        let p = build_fir_legacy(1);
        let a = s.protect(&p).unwrap();
        assert_eq!(&a[8..12], &0x80000000u32.to_be_bytes());
        assert_eq!(a.len(), 22);
    }
    #[test]
    fn independent_node_crypto_vectors() {
        let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let k = derive(&[9; 46], 0).unwrap();
        assert_eq!(
            hex(&k.cipher),
            "f4350c1babeeea98eac9dd95646d07828cf458452ac03f5a7dc4669261142785"
        );
        assert_eq!(hex(&k.auth), "d5d593fee722b3828f4bd3adbd740806eb1bec85");
        assert_eq!(hex(&k.salt), "fbb490198b3e3bbc745e0804a73e");
        let wire = "8060ffff0000000100000007130dc0f57a34f3760ad844e3";
        let wire: Vec<u8> = (0..wire.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
            .collect();
        let mut receiver = SrtpReceiver::new(&[9; 46]).unwrap();
        assert_eq!(
            receiver.unprotect(&wire).unwrap().unwrap().payload,
            vec![4, 5]
        );
        let mut s = SrtcpSender::new(&[9; 46]).unwrap();
        assert_eq!(
            hex(&s.protect(&build_fir_legacy(7)).unwrap()),
            "80c000010000000780000000ad143750d8b447dccf07"
        );
    }
}
