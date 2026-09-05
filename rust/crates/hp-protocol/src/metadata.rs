use anyhow::{ensure, Result};
use flate2::read::ZlibDecoder;
use std::io::Read;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    pub width: u16,
    pub height: u16,
    pub tile_count: u16,
    pub ltr_enabled: bool,
}
fn varint(b: &[u8], p: &mut usize) -> Result<u64> {
    let mut v = 0;
    for shift in (0..70).step_by(7) {
        ensure!(*p < b.len(), "truncated protobuf varint");
        let c = b[*p];
        *p += 1;
        ensure!(shift != 63 || c <= 1, "protobuf varint overflow");
        v |= ((c & 127) as u64) << shift;
        if c & 128 == 0 {
            return Ok(v);
        }
    }
    anyhow::bail!("invalid protobuf varint")
}
type ProtoField<'a> = (u64, Option<u64>, &'a [u8]);
pub(crate) fn fields(b: &[u8]) -> Result<Vec<ProtoField<'_>>> {
    ensure!(b.len() <= 1024 * 1024, "protobuf exceeds input limit");
    let mut p = 0;
    let mut out = Vec::new();
    while p < b.len() {
        ensure!(out.len() < 4096, "protobuf field count exceeds limit");
        let tag = varint(b, &mut p)?;
        let field = tag >> 3;
        ensure!(field != 0, "invalid protobuf field");
        let (value, length) = match tag & 7 {
            0 => (Some(varint(b, &mut p)?), 0),
            1 => (None, 8),
            2 => (None, usize::try_from(varint(b, &mut p)?)?),
            5 => (None, 4),
            _ => anyhow::bail!("unsupported protobuf wire type"),
        };
        ensure!(length <= b.len() - p, "truncated protobuf field");
        out.push((field, value, &b[p..p + length]));
        p += length;
    }
    Ok(out)
}
fn video_config(b: &[u8]) -> Result<Option<StreamConfig>> {
    for (field, _, sub) in fields(b)? {
        if field != 5 {
            continue;
        }
        // Apple omits F6 for a single full-picture stream. An explicit zero is
        // still invalid; default only the absent field to one (live verified).
        let (mut w, mut h, mut tiles, mut ltr) = (0, 0, 1, false);
        for (f, v, _) in fields(sub)? {
            if let Some(v) = v {
                match f {
                    4 => w = v,
                    5 => h = v,
                    6 => tiles = v,
                    7 => ltr = v != 0,
                    _ => {}
                }
            }
        }
        if w > 0 && h > 0 {
            ensure!(
                w <= 16384 && h <= 16384 && w * h <= 67_108_864,
                "HP canvas exceeds limits"
            );
            ensure!((1..=64).contains(&tiles), "invalid negotiated tile count");
            return Ok(Some(StreamConfig {
                width: w as u16,
                height: h as u16,
                tile_count: tiles as u16,
                ltr_enabled: ltr,
            }));
        }
    }
    Ok(None)
}
/// The enclosing Apple structure has undocumented variable records. Locate a
/// plist anchor, then accept only bounded zlib+protobuf geometry underneath it.
/// This intentionally does not trust an arbitrary byte pair as a geometry value.
pub fn parse_answer(body: &[u8]) -> Result<Option<StreamConfig>> {
    ensure!(
        body.len() <= 65498,
        "media answer exceeds control record limit"
    );
    if body.first() != Some(&0) {
        return Ok(None);
    }
    let Some(start) = body.windows(8).position(|w| w == b"bplist00") else {
        return Ok(None);
    };
    let (mut attempts, mut expanded) = (0, 0usize);
    for i in start..body.len().saturating_sub(1) {
        if body[i] != 0x78 || !u16::from_be_bytes([body[i], body[i + 1]]).is_multiple_of(31) {
            continue;
        }
        attempts += 1;
        ensure!(attempts <= 32, "media answer zlib candidate limit exceeded");
        let mut out = Vec::new();
        let mut decoder = ZlibDecoder::new(&body[i..]).take((1024 * 1024 - expanded + 1) as u64);
        let decoded = decoder.read_to_end(&mut out);
        expanded += out.len();
        ensure!(expanded <= 1024 * 1024, "media answer expands beyond limit");
        if decoded.is_err() {
            continue;
        }
        if let Ok(Some(config)) = video_config(&out) {
            return Ok(Some(config));
        }
    }
    Ok(None)
}
/// Metadata-only troubleshooting: reports only dimensions, counts and our own
/// parser result, never server text, media bytes, keys, or encoded payloads.
pub(crate) fn diagnose_answer(body: &[u8]) -> String {
    if body.len() > 65498 {
        return "reason=oversize_record".into();
    }
    let mut compressed = 0;
    let mut protobuf = 0;
    let mut configs = 0;
    let (mut width, mut height, mut tiles) = (0, 0, None);
    let mut reason = "no_video_config";
    let (mut attempts, mut expanded) = (0, 0usize);
    if let Some(start) = body.windows(8).position(|w| w == b"bplist00") {
        for i in start..body.len().saturating_sub(1) {
            if body[i] != 0x78 || !u16::from_be_bytes([body[i], body[i + 1]]).is_multiple_of(31) {
                continue;
            }
            attempts += 1;
            if attempts > 32 {
                reason = "zlib_candidate_limit";
                break;
            }
            let mut out = Vec::new();
            let decoded = ZlibDecoder::new(&body[i..])
                .take((1024 * 1024 - expanded + 1) as u64)
                .read_to_end(&mut out);
            expanded += out.len();
            if expanded > 1024 * 1024 {
                reason = "decompression_limit";
                break;
            }
            if decoded.is_err() {
                continue;
            }
            compressed += 1;
            let Ok(top) = fields(&out) else {
                reason = "invalid_protobuf";
                continue;
            };
            protobuf += 1;
            for (f, _, sub) in top {
                if f != 5 {
                    continue;
                }
                let Ok(config) = fields(sub) else {
                    reason = "invalid_video_config";
                    continue;
                };
                configs += 1;
                for (f, v, _) in config {
                    match (f, v) {
                        (4, Some(v)) => width = v,
                        (5, Some(v)) => height = v,
                        (6, Some(v)) => tiles = Some(v),
                        _ => {}
                    }
                }
                reason = if width == 0 || height == 0 {
                    "zero_geometry"
                } else if width > 16384 || height > 16384 || width * height > 67_108_864 {
                    "oversize_geometry"
                } else if tiles.is_none() {
                    "tile_field_missing"
                } else if !matches!(tiles, Some(1..=64)) {
                    "invalid_tile_count"
                } else {
                    "valid_geometry"
                };
            }
        }
    }
    format!("type={}, zlib={compressed}, protobuf={protobuf}, video_configs={configs}, geometry={width}x{height}, tiles={tiles:?}, reason={reason}",body.first().copied().unwrap_or(255))
}
/// Returns true only when every rectangle is bounded and the update is complete.
pub fn complete_update(body: &[u8]) -> bool {
    scan_update(body).0
}
pub fn display_layout(body: &[u8]) -> Option<(u16, u16)> {
    let (complete, layout) = scan_update(body);
    if complete {
        layout
    } else {
        None
    }
}
fn scan_update(body: &[u8]) -> (bool, Option<(u16, u16)>) {
    let mut layout = None;
    if body.len() < 4 || body[0] != 0 {
        return (false, None);
    }
    let n = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut p = 4;
    for _ in 0..n {
        if body.len() - p < 12 {
            return (false, None);
        }
        let enc = i32::from_be_bytes(body[p + 8..p + 12].try_into().unwrap());
        p += 12;
        if enc == -224 {
            return (true, layout);
        }
        let rest = &body[p..];
        let size = match enc {
            1103 => 36,
            0x450 if rest.len() >= 8 => {
                8usize.saturating_add(u32::from_be_bytes(rest[4..8].try_into().unwrap()) as usize)
            }
            1002 | 1010 | 1011 | 0x451 | 0x453 | 0x455 | 0x456 if rest.len() >= 2 => {
                2 + u16::from_be_bytes([rest[0], rest[1]]) as usize
            }
            -223 => 0,
            _ => return (false, None),
        };
        if size > body.len() - p {
            return (false, None);
        }
        if enc == 0x451 {
            let payload = &rest[2..size];
            if payload.len() < 20 {
                return (false, None);
            }
            let count = u16::from_be_bytes([payload[18], payload[19]]) as usize;
            if payload.len() < 20 + count * 56 {
                return (false, None);
            }
            let w = u16::from_be_bytes([payload[6], payload[7]]);
            let h = u16::from_be_bytes([payload[8], payload[9]]);
            if w > 0
                && h > 0
                && w <= 16384
                && h <= 16384
                && u32::from(w) * u32::from(h) <= 67_108_864
            {
                layout = Some((w, h));
            }
        }
        p += size;
    }
    (p == body.len(), layout)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn many_small_protobuf_fields_are_bounded() {
        let body = [8, 0].repeat(4097);
        assert!(fields(&body).is_err());
    }
    #[test]
    fn compressed_candidate_scan_is_bounded() {
        let mut body = b"\0bplist00".to_vec();
        body.extend([0x78, 0x9c, 0xff, 0xff].repeat(33));
        assert!(parse_answer(&body).is_err());
        assert!(diagnose_answer(&body).contains("zlib_candidate_limit"));
    }
    #[test]
    fn decompression_bomb_rejected() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&vec![0; 1024 * 1024 + 1]).unwrap();
        let mut body = b"\0bplist00".to_vec();
        body.extend(z.finish().unwrap());
        assert!(parse_answer(&body).is_err());
        assert!(diagnose_answer(&body).contains("decompression_limit"));
    }
    #[test]
    fn diagnostics_distinguish_missing_tile_count_from_zero() {
        use std::io::Write;
        for (proto, expected) in [
            (
                &[42, 6, 32, 128, 15, 40, 184, 8][..],
                "tiles=None, reason=tile_field_missing",
            ),
            (
                &[42, 8, 32, 128, 15, 40, 184, 8, 48, 0][..],
                "tiles=Some(0), reason=invalid_tile_count",
            ),
        ] {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(proto).unwrap();
            let mut body = b"\0bplist00".to_vec();
            body.extend(z.finish().unwrap());
            assert!(diagnose_answer(&body).contains(expected));
        }
    }
    #[test]
    fn layout_requires_all_declared_display_records() {
        let mut b = vec![0; 38];
        b[3] = 1;
        b[12..16].copy_from_slice(&0x451i32.to_be_bytes());
        b[16..18].copy_from_slice(&20u16.to_be_bytes());
        b[24..26].copy_from_slice(&1920u16.to_be_bytes());
        b[26..28].copy_from_slice(&1080u16.to_be_bytes());
        assert_eq!(display_layout(&b), Some((1920, 1080)));
        for n in 0..b.len() {
            assert!(!complete_update(&b[..n]));
        }
        b[37] = 1;
        assert_eq!(display_layout(&b), None);
        b.extend([0; 56]);
        b[16..18].copy_from_slice(&76u16.to_be_bytes());
        assert_eq!(display_layout(&b), Some((1920, 1080)));
        // Following length-prefixed config rectangles must not shift the next header.
        b[3] = 4;
        for encoding in [0x453i32, 0x455, 0x456] {
            b.extend([0; 8]);
            b.extend(encoding.to_be_bytes());
            b.extend([0, 3, 1, 2, 3]);
        }
        assert!(complete_update(&b));
        assert_eq!(display_layout(&b), Some((1920, 1080)));
        for n in 0..b.len() {
            assert!(!complete_update(&b[..n]));
        }
    }
    #[test]
    fn answer_decodes_bounded_compressed_geometry() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&[42, 10, 32, 128, 15, 40, 184, 8, 48, 4, 56, 0])
            .unwrap();
        let mut body = b"\0\0\0\0bplist00".to_vec();
        body.extend(z.finish().unwrap());
        let config = parse_answer(&body).unwrap().unwrap();
        assert_eq!(
            (config.width, config.height, config.tile_count),
            (1920, 1080, 4)
        );
        assert_eq!(parse_answer(&body[..10]).unwrap(), None);
    }
    #[test]
    fn protobuf_rejects_truncation_and_overflow() {
        assert!(fields(&[10, 100, 2]).is_err());
        assert!(fields(&[8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2]).is_err());
    }
    #[test]
    fn geometry_fields() {
        let omitted = video_config(&[42, 6, 32, 128, 15, 40, 184, 8])
            .unwrap()
            .unwrap();
        assert_eq!(omitted.tile_count, 1);
        assert!(
            video_config(&[42, 8, 32, 128, 15, 40, 184, 8, 48, 0]).is_err(),
            "explicit zero must not be silently normalized"
        );
        let one = video_config(&[42, 10, 32, 128, 15, 40, 184, 8, 48, 1, 56, 0])
            .unwrap()
            .unwrap();
        assert_eq!(
            one.tile_count, 1,
            "single-picture answers must not depend on the legacy four-tile count"
        );
        assert_eq!(
            video_config(&[42, 10, 32, 128, 15, 40, 184, 8, 48, 4, 56, 0]).unwrap(),
            Some(StreamConfig {
                width: 1920,
                height: 1080,
                tile_count: 4,
                ltr_enabled: false
            })
        );
    }
    #[test]
    fn only_complete_updates_rearm() {
        let msg = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 32];
        for n in 0..msg.len() {
            assert!(!complete_update(&msg[..n]));
        }
        assert!(complete_update(&msg));
    }
}
