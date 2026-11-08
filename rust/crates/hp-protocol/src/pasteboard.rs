//! Apple rich pasteboard sync, Mac → viewer direction (text only).
//!
//! Wire behaviour follows two independent implementations that agree on these
//! bytes (see docs/FILE_TRANSFER_RESEARCH.md): iShareScreen's
//! `proxy/protocol/clipboard.py` and noVNC-ARD's `ard-patch.js`.
//!
//! - `0x15` AutoPasteboard, client → Mac, 8 bytes: `[0x15, 0, cmd u16 BE = 1, 0×4]`
//!   asks the Mac to watch its pasteboard and announce changes.
//! - `0x14` state change, Mac → client: `[0x14, 0, size u16, flags u16, status u16]`;
//!   status 2 means the Mac pasteboard changed.
//! - `0x0b` clipboard request, client → Mac, exactly 8 bytes, all zero after the
//!   type: fetch the full pasteboard. (Nine bytes desynchronise the Mac's parser.)
//! - `0x1f` clipboard send, Mac → client: 16-byte header
//!   `[0x1f, 0, promise, 0, session u32, uncompressed u32, compressed u32]`
//!   then a zlib stream ending in a sync flush (no final block). One logical
//!   message can span several encrypted records; only the first has the header.
//!
//! The decompressed archive is `u32 count` then per item: `u32 len, uti`,
//! `u32 reserved`, `u32 alias_count`, aliases as `(u32 len, name, u32 len, value)`,
//! `u32 len, data`. All integers are big-endian.
//!
//! Everything is bounded: an oversized or malformed pasteboard is skipped and
//! never ends the screen-sharing session.

use anyhow::{ensure, Context, Result};
use flate2::{Decompress, FlushDecompress, Status};

/// Ask the Mac to announce pasteboard changes.
pub const ENABLE: [u8; 8] = [0x15, 0, 0, 1, 0, 0, 0, 0];
/// Fetch the full Mac pasteboard.
pub const FETCH: [u8; 8] = [0x0b, 0, 0, 0, 0, 0, 0, 0];
const SEND: u8 = 0x1f;
const HEADER: usize = 16;
/// Largest compressed pasteboard kept; larger ones are skipped byte-for-byte.
pub const MAX_COMPRESSED: usize = 16 * 1024 * 1024;
/// Largest decompressed pasteboard archive decoded.
pub const MAX_EXPANDED: usize = 32 * 1024 * 1024;
const MAX_ITEMS: u32 = 4096;
const MAX_ALIASES: u32 = 256;
const MAX_NAME: u32 = 1024;

/// True for the Mac's "pasteboard changed" state message.
pub fn is_changed_notice(body: &[u8]) -> bool {
    body.len() >= 8 && body[0] == 0x14 && u16::from_be_bytes([body[6], body[7]]) == 2
}

/// Reassembles one `0x1f` message from consecutive control-record bodies.
#[derive(Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    expected: usize,
    received: usize,
    keep: bool,
}
pub struct Fed {
    /// The complete message, when it finished within the size limit.
    pub complete: Option<Vec<u8>>,
    /// Bytes in the final record after this message, to be handled as usual.
    pub rest: Option<Vec<u8>>,
}
impl Reassembler {
    pub fn in_progress(&self) -> bool {
        self.expected != 0
    }
    /// True when `body` starts a pasteboard message.
    pub fn starts(body: &[u8]) -> bool {
        body.len() >= HEADER && body[0] == SEND
    }
    /// Call only when `in_progress()` or `starts(body)`.
    pub fn feed(&mut self, body: &[u8]) -> Fed {
        if !self.in_progress() {
            let compressed = u32::from_be_bytes(body[12..16].try_into().unwrap()) as usize;
            self.expected = HEADER + compressed;
            self.received = 0;
            self.keep = compressed <= MAX_COMPRESSED;
            self.buffer.clear();
        }
        let take = (self.expected - self.received).min(body.len());
        if self.keep {
            self.buffer.extend_from_slice(&body[..take]);
        }
        self.received += take;
        let rest = (take < body.len()).then(|| body[take..].to_vec());
        if self.received < self.expected {
            return Fed {
                complete: None,
                rest,
            };
        }
        self.expected = 0;
        let complete = self.keep.then(|| std::mem::take(&mut self.buffer));
        Fed { complete, rest }
    }
}

/// The text a complete `0x1f` message carries, if any text flavour is present.
pub fn decode_text(message: &[u8]) -> Result<Option<String>> {
    ensure!(
        message.len() >= HEADER && message[0] == SEND,
        "not a pasteboard message"
    );
    let expanded = u32::from_be_bytes(message[8..12].try_into()?) as usize;
    let compressed = u32::from_be_bytes(message[12..16].try_into()?) as usize;
    ensure!(
        message.len() == HEADER + compressed,
        "truncated pasteboard message"
    );
    ensure!(expanded <= MAX_EXPANDED, "pasteboard too large");
    if expanded == 0 {
        return Ok(None); // Empty Mac pasteboard.
    }
    let archive = inflate(&message[HEADER..], expanded)?;
    text_from_items(&parse_items(&archive)?)
}

/// Inflates a zlib stream that may end with a sync flush instead of a final block.
fn inflate(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut inflater = Decompress::new(true);
    // One spare byte detects an archive longer than its declared size.
    let mut output = Vec::with_capacity(expected + 1);
    loop {
        let (before_in, before_out) = (inflater.total_in() as usize, output.len());
        let status = inflater
            .decompress_vec(&input[before_in..], &mut output, FlushDecompress::Sync)
            .context("corrupt pasteboard data")?;
        ensure!(output.len() <= expected, "pasteboard larger than declared");
        if status == Status::StreamEnd || inflater.total_in() as usize == input.len() {
            break;
        }
        ensure!(
            inflater.total_in() as usize > before_in || output.len() > before_out,
            "corrupt pasteboard data"
        );
    }
    ensure!(output.len() == expected, "pasteboard size mismatch");
    Ok(output)
}

struct Item<'a> {
    uti: &'a [u8],
    data: &'a [u8],
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Result<u32> {
        let end = self.at.checked_add(4).context("pasteboard overflow")?;
        let value = self
            .bytes
            .get(self.at..end)
            .context("truncated pasteboard")?;
        self.at = end;
        Ok(u32::from_be_bytes(value.try_into()?))
    }
    fn bytes(&mut self, limit: u32) -> Result<&'a [u8]> {
        let n = self.u32()?;
        ensure!(n <= limit, "pasteboard field too large");
        let end = self
            .at
            .checked_add(n as usize)
            .context("pasteboard overflow")?;
        let value = self
            .bytes
            .get(self.at..end)
            .context("truncated pasteboard")?;
        self.at = end;
        Ok(value)
    }
}
fn parse_items(archive: &[u8]) -> Result<Vec<Item<'_>>> {
    if archive.len() < 4 {
        return Ok(vec![]);
    }
    let mut cursor = Cursor {
        bytes: archive,
        at: 0,
    };
    let count = cursor.u32()?;
    ensure!(count <= MAX_ITEMS, "too many pasteboard items");
    let mut items = Vec::new();
    for _ in 0..count {
        let uti = cursor.bytes(MAX_NAME)?;
        let _reserved = cursor.u32()?;
        let aliases = cursor.u32()?;
        ensure!(aliases <= MAX_ALIASES, "too many pasteboard aliases");
        for _ in 0..aliases {
            cursor.bytes(MAX_NAME)?;
            cursor.bytes(MAX_EXPANDED as u32)?;
        }
        let data = cursor.bytes(MAX_EXPANDED as u32)?;
        items.push(Item { uti, data });
    }
    Ok(items)
}

/// Same preference order as the reference viewers: UTF-8 plain text, any other
/// public text flavour, then legacy Mac Roman/Latin-1 text.
fn text_from_items(items: &[Item]) -> Result<Option<String>> {
    if let Some(item) = items.iter().find(|i| i.uti == b"public.utf8-plain-text") {
        return Ok(Some(String::from_utf8_lossy(item.data).into_owned()));
    }
    for item in items {
        let uti = String::from_utf8_lossy(item.uti);
        if uti.starts_with("public.") && uti.contains("text") {
            if uti.contains("utf16") {
                let big_endian = uti.contains("external");
                let units: Vec<u16> = item
                    .data
                    .chunks_exact(2)
                    .map(|c| {
                        if big_endian {
                            u16::from_be_bytes([c[0], c[1]])
                        } else {
                            u16::from_le_bytes([c[0], c[1]])
                        }
                    })
                    .collect();
                return Ok(Some(String::from_utf16_lossy(&units)));
            }
            // Rich formats (public.rtf, public.html) are text flavours but not
            // plain text; only accept them when nothing plainer exists.
            if uti == "public.plain-text" || uti.ends_with("plain-text") {
                return Ok(Some(String::from_utf8_lossy(item.data).into_owned()));
            }
        }
    }
    if let Some(item) = items
        .iter()
        .find(|i| i.uti == b"com.apple.traditional-mac-plain-text")
    {
        return Ok(Some(item.data.iter().map(|&b| b as char).collect()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn archive(items: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = (items.len() as u32).to_be_bytes().to_vec();
        for (uti, data) in items {
            out.extend((uti.len() as u32).to_be_bytes());
            out.extend(uti.as_bytes());
            out.extend(0u32.to_be_bytes());
            out.extend(1u32.to_be_bytes()); // one alias, skipped
            out.extend(4u32.to_be_bytes());
            out.extend(b"name");
            out.extend(3u32.to_be_bytes());
            out.extend(b"val");
            out.extend((data.len() as u32).to_be_bytes());
            out.extend(*data);
        }
        out
    }
    /// Compresses like the Mac: zlib header, sync flush, no final block.
    fn message(inner: &[u8]) -> Vec<u8> {
        let mut compress = Compress::new(Compression::default(), true);
        let mut compressed = Vec::with_capacity(inner.len() + 64);
        compress
            .compress_vec(inner, &mut compressed, FlushCompress::Sync)
            .unwrap();
        let mut out = vec![SEND, 0, 0, 0, 0, 0, 0, 7];
        out.extend((inner.len() as u32).to_be_bytes());
        out.extend((compressed.len() as u32).to_be_bytes());
        out.extend(compressed);
        out
    }

    #[test]
    fn control_messages_match_reference_bytes() {
        assert_eq!(ENABLE, [0x15, 0x00, 0x00, 0x01, 0, 0, 0, 0]);
        assert_eq!(FETCH.len(), 8, "nine bytes desynchronise the Mac parser");
        assert!(is_changed_notice(&[0x14, 0, 0, 4, 0, 1, 0, 2]));
        assert!(!is_changed_notice(&[0x14, 0, 0, 4, 0, 1, 0, 12]));
        assert!(!is_changed_notice(&[0x14, 0, 0, 4]));
    }

    #[test]
    fn decodes_utf8_text_split_across_records() {
        let text = "Hello from the Mac — 你好 ✓\nline 2";
        let full = message(&archive(&[
            ("public.rtf", b"{\\rtf1 not this}"),
            ("public.utf8-plain-text", text.as_bytes()),
        ]));
        let mut r = Reassembler::default();
        let (a, b) = full.split_at(20);
        let (b, c) = b.split_at(5);
        assert!(Reassembler::starts(a));
        assert!(r.feed(a).complete.is_none());
        assert!(r.in_progress());
        assert!(r.feed(b).complete.is_none());
        let mut tail = c.to_vec();
        tail.extend([0x14, 0, 0, 4, 0, 1, 0, 2]);
        let fed = r.feed(&tail);
        assert!(!r.in_progress());
        assert_eq!(
            fed.rest.as_deref(),
            Some(&[0x14, 0, 0, 4, 0, 1, 0, 2][..]),
            "a following message in the same record is kept"
        );
        assert_eq!(
            decode_text(&fed.complete.unwrap()).unwrap().as_deref(),
            Some(text)
        );
    }

    #[test]
    fn falls_back_to_utf16_and_legacy_text() {
        let utf16: Vec<u8> = "héllo"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let full = message(&archive(&[("public.utf16-external-plain-text", &utf16)]));
        assert_eq!(decode_text(&full).unwrap().as_deref(), Some("héllo"));
        let full = message(&archive(&[(
            "com.apple.traditional-mac-plain-text",
            &[b'c', b'a', b'f', 0xe9],
        )]));
        assert_eq!(decode_text(&full).unwrap().as_deref(), Some("café"));
    }

    #[test]
    fn non_text_and_empty_pasteboards_yield_nothing() {
        let full = message(&archive(&[("public.png", &[0x89, b'P', b'N', b'G'])]));
        assert_eq!(decode_text(&full).unwrap(), None);
        let mut empty = vec![SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        empty.extend(2u32.to_be_bytes());
        empty.extend([0x03, 0x00]);
        assert_eq!(decode_text(&empty).unwrap(), None);
    }

    #[test]
    fn malformed_pasteboards_are_rejected_not_trusted() {
        let mut full = message(&archive(&[("public.utf8-plain-text", b"hi")]));
        // Declared expanded size smaller than the real archive.
        full[11] = full[11].wrapping_sub(1);
        assert!(decode_text(&full).is_err());
        // Item length beyond the archive.
        let mut bad = archive(&[("public.utf8-plain-text", b"hi")]);
        let n = bad.len();
        bad[n - 6..n - 2].copy_from_slice(&1000u32.to_be_bytes());
        assert!(decode_text(&message(&bad)).is_err());
        // Garbage instead of a zlib stream.
        let mut junk = vec![SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4];
        junk.extend([0xde, 0xad, 0xbe, 0xef]);
        assert!(decode_text(&junk).is_err());
    }

    #[test]
    fn oversized_pasteboard_is_skipped_without_buffering() {
        let mut header = vec![SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        header.extend(((MAX_COMPRESSED + 10) as u32).to_be_bytes());
        let mut r = Reassembler::default();
        assert!(r.feed(&header).complete.is_none());
        let chunk = vec![0u8; MAX_COMPRESSED / 2];
        assert!(r.feed(&chunk).complete.is_none());
        assert!(r.feed(&chunk).complete.is_none());
        assert!(r.buffer.is_empty());
        let fed = r.feed(&[0u8; 20]);
        assert!(fed.complete.is_none(), "oversized message is dropped");
        assert_eq!(fed.rest.map(|r| r.len()), Some(10));
        assert!(!r.in_progress());
    }
}
