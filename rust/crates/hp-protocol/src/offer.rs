use anyhow::Result;
use flate2::{write::ZlibEncoder, Compression};
use plist::{Dictionary, Value};
use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
pub(crate) fn varint(mut v: u64) -> Vec<u8> {
    let mut o = Vec::new();
    while v > 127 {
        o.push(v as u8 | 128);
        v >>= 7;
    }
    o.push(v as u8);
    o
}
fn v(n: u64, value: u64) -> Vec<u8> {
    [varint(n << 3), varint(value)].concat()
}
fn b(n: u64, value: &[u8]) -> Vec<u8> {
    [
        varint((n << 3) | 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn offer(mode: u64, ssrc: u32) -> Result<Vec<u8>> {
    let desc = if mode == 7 {
        let r = [v(1, 1), v(2, 1), v(3, 50115), v(4, 0)].concat();
        let alt = [v(1, 1), v(2, 2), v(3, 50115), v(4, 0)].concat();
        // LTR is deliberately disabled until acknowledgements are implemented.
        // Apple maps these bank IDs opposite to their historical parameter names.
        // Upstream offers.py live verification: bank 123 yields H.264, while bank
        // 100 + AVC-labelled parameters yields HEVC 4:4:4. Select by OUTPUT codec.
        let bank = [
            v(1, 100),
            b(2, &r),
            b(2, &alt),
            b(
                3,
                b"FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;",
            ),
            v(4, 14),
        ]
        .concat();
        b(
            5,
            &[
                v(1, ssrc as u64),
                v(2, 0),
                b(3, &bank),
                // One independently decodable picture avoids Apple's cross-tile
                // reference/compositing semantics. This remains HP over SRTP/HEVC.
                v(6, 1),
                v(7, 0),
                v(8, 63),
                v(9, 1),
                v(12, 1),
            ]
            .concat(),
        )
    } else {
        b(
            3,
            &[
                v(1, ssrc as u64),
                v(2, 0),
                v(3, 0),
                v(4, 1000),
                v(5, 0),
                v(6, 0),
            ]
            .concat(),
        )
    };
    let tiers = [
        (0, 40_000_000, Some(12288)),
        (0, 6_000_000, Some(131072)),
        (4074, 0, Some(16384)),
        (16, 4100, None),
        (0, 75_000_000, Some(524288)),
        (0, 20_000_000, Some(98304)),
        (4, 6500, None),
        (0, 60_000_000, Some(262144)),
        (1, 299, None),
        (0, 100_000_000, Some(1048576)),
    ];
    let mut media = [v(1, 1), v(2, 1), desc, b(6, b"iShareScreen 1.0.0"), v(8, 0)].concat();
    for (a, c, d) in tiers {
        let mut t = [v(1, a), v(2, c)].concat();
        if let Some(d) = d {
            t.extend(v(3, d));
        }
        media.extend(b(9, &t));
    }
    let ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    media.extend([v(13, ns), v(14, 2), v(16, 0), v(18, 1)].concat());
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(&media)?;
    let compressed = z.finish()?;
    let endpoint = [
        v(1, 0),
        v(2, 1),
        b(3, b"MacBookPro18,3"),
        b(4, b"1.0.0"),
        b(5, b"24A335"),
    ]
    .concat();
    let mut dict = Dictionary::new();
    dict.insert(
        "avcMediaStreamNegotiatorMediaBlob".into(),
        Value::Data(compressed),
    );
    dict.insert(
        "avcMediaStreamNegotiatorMode".into(),
        Value::Integer(mode.into()),
    );
    dict.insert(
        "avcMediaStreamOptionCallID".into(),
        Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
    );
    dict.insert(
        "avcMediaStreamOptionRemoteEndpointInfo".into(),
        Value::Data(endpoint),
    );
    let mut out = Vec::new();
    Value::Dictionary(dict).to_writer_binary(&mut out)?;
    Ok(out)
}
pub(crate) fn media_options(
    ssrc: u32,
    send: &[u8; 46],
    recv: &[u8; 46],
    fps: u16,
    audio_ssrc: u32,
    audio_send: &[u8; 46],
) -> Result<Vec<u8>> {
    use rand::RngCore;
    let audio = offer(8, audio_ssrc)?;
    let video = offer(7, ssrc)?;
    let size = audio.len() + video.len() + 0xd8;
    let mut out = vec![0; size + 4];
    out[0] = 0x1c;
    put16(&mut out, 2, size as u16);
    put16(&mut out, 4, 3);
    put32(&mut out, 6, if fps >= 60 { 7 } else { 3 });
    put16(&mut out, 10, audio.len() as u16);
    put16(&mut out, 12, video.len() as u16);
    rand::rngs::OsRng.fill_bytes(&mut out[0x14..0x80]);
    out[0x24..0x52].copy_from_slice(audio_send);
    out[0x80..0x80 + audio.len()].copy_from_slice(&audio);
    let p = 0x80 + audio.len();
    out[p..p + 46].copy_from_slice(send);
    out[p + 46..p + 92].copy_from_slice(recv);
    out[p + 92..].copy_from_slice(&video);
    Ok(out)
}
pub(crate) fn put16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_be_bytes());
}
pub(crate) fn auto_fbu(w: u16, h: u16) -> Vec<u8> {
    let mut out = vec![0; 16];
    out[0] = 9;
    out[3] = 1;
    put32(&mut out, 4, u32::MAX);
    put16(&mut out, 12, w);
    put16(&mut out, 14, h);
    out
}
pub(crate) fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_be_bytes());
}
pub(crate) fn viewer_info() -> Vec<u8> {
    let mut b = vec![0; 66];
    b[0] = 0x21;
    put16(&mut b, 2, 62);
    put16(&mut b, 4, 1);
    for (p, v) in [(6, 2), (10, 6), (14, 1), (22, 15), (26, 3)] {
        put32(&mut b, p, v);
    }
    for (p, v) in [(34, 0xb0), (36, 0x0c), (37, 3), (38, 0x90), (44, 0x40)] {
        b[p] = v;
    }
    b
}
pub(crate) fn encodings() -> Vec<u8> {
    let ids: [i32; 13] = [
        1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110,
    ];
    let mut out = vec![2, 0, 0, 13];
    for id in ids {
        out.extend(id.to_be_bytes());
    }
    out
}
pub(crate) fn display_config(w: u16, h: u16, fps: u16) -> Vec<u8> {
    let mut b = vec![0; 308];
    b[0] = 0x1d;
    put16(&mut b, 2, 304);
    put16(&mut b, 4, 1);
    put16(&mut b, 6, 1);
    let d = 12;
    put16(&mut b, d, 296);
    b[d + 2..d + 8].copy_from_slice(b"macvnc");
    for (p, v) in [
        (0x7a, 1),
        (0x7e, 4),
        (0x82, 369.45456f32.to_bits()),
        (0x86, 207.81818f32.to_bits()),
        (0x8a, 3840u32.max(w as u32)),
        (0x8e, 2160u32.max(h as u32)),
        (0x96, 7),
    ] {
        put32(&mut b, d + p, v);
    }
    put16(&mut b, d + 0x9a, 5);
    for (i, (w, h)) in [(w, h), (1440, 900), (1920, 1080), (1440, 810), (1312, 848)]
        .iter()
        .enumerate()
    {
        let m = d + 0x9c + 28 * i;
        for (p, v) in [(0, *w), (4, *h), (8, *w), (12, *h)] {
            put32(&mut b, m + p, v as u32);
        }
        b[m + 16..m + 24].copy_from_slice(&(fps as f64).to_be_bytes());
    }
    b
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hevc_offer_uses_apple_output_mapping_not_bank_label() {
        use std::io::{Cursor, Read};
        let plist = Value::from_reader(Cursor::new(offer(7, 42).unwrap())).unwrap();
        let compressed = plist.as_dictionary().unwrap()["avcMediaStreamNegotiatorMediaBlob"]
            .as_data()
            .unwrap();
        let mut proto = Vec::new();
        flate2::read::ZlibDecoder::new(compressed)
            .read_to_end(&mut proto)
            .unwrap();
        let desc = crate::metadata::fields(&proto)
            .unwrap()
            .into_iter()
            .find(|f| f.0 == 5)
            .unwrap()
            .2;
        assert_eq!(
            crate::metadata::fields(desc)
                .unwrap()
                .iter()
                .find(|f| f.0 == 6)
                .unwrap()
                .1,
            Some(1),
            "request independently decodable full pictures, not cross-tile references"
        );
        let banks: Vec<_> = crate::metadata::fields(desc)
            .unwrap()
            .into_iter()
            .filter(|f| f.0 == 3)
            .collect();
        assert_eq!(banks.len(), 1);
        let bank = crate::metadata::fields(banks[0].2).unwrap();
        assert_eq!(
            bank.iter().find(|f| f.0 == 1).unwrap().1,
            Some(100),
            "123 actually selects H.264 and starves HEVC depacketization"
        );
        assert_eq!(bank.iter().find(|f| f.0 == 4).unwrap().1, Some(14));
        assert_eq!(bank.iter().filter(|f| f.0 == 2).count(), 2);
    }
    #[test]
    fn unsigned_varint() {
        assert_eq!(varint(u32::MAX as u64), [255, 255, 255, 255, 15]);
    }
    #[test]
    fn media_layout() {
        use std::io::{Cursor, Read};
        let b = media_options(123, &[1; 46], &[2; 46], 60, 321, &[3; 46]).unwrap();
        assert_eq!(
            &b[0x24..0x52],
            &[3; 46],
            "audio heartbeat key must match the negotiated audio send key"
        );
        assert_eq!(b[0], 28);
        let a = u16::from_be_bytes([b[10], b[11]]) as usize;
        let audio_plist = Value::from_reader(Cursor::new(&b[0x80..0x80 + a])).unwrap();
        let compressed = audio_plist.as_dictionary().unwrap()["avcMediaStreamNegotiatorMediaBlob"]
            .as_data()
            .unwrap();
        let mut proto = Vec::new();
        flate2::read::ZlibDecoder::new(compressed)
            .read_to_end(&mut proto)
            .unwrap();
        let audio_config = crate::metadata::fields(&proto)
            .unwrap()
            .into_iter()
            .find(|f| f.0 == 3)
            .unwrap()
            .2;
        let audio_fields = crate::metadata::fields(audio_config).unwrap();
        assert_eq!(
            audio_fields.iter().find(|f| f.0 == 1).unwrap().1,
            Some(321),
            "heartbeat RTP source must equal offered audio SSRC"
        );
        assert_eq!(
            audio_fields.iter().find(|f| f.0 == 4).unwrap().1,
            Some(1000),
            "heartbeat negotiation does not enable system-audio recording"
        );
        assert_eq!(&b[0x80 + a..0x80 + a + 46], &[1; 46]);
        assert_eq!(&b[0x80 + a + 46..0x80 + a + 92], &[2; 46]);
    }
    #[test]
    fn display_dimensions() {
        let b = display_config(2560, 1440, 30);
        assert_eq!(&b[168..172], &2560u32.to_be_bytes());
    }
}
