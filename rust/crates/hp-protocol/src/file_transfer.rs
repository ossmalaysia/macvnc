//! Experimental Apple 0x22 file messages, sent only after normal HP login.
//!
//! Wire-field facts were independently transcribed from the public references
//! in docs/FILE_TRANSFER_RESEARCH.md. No authentication-bypass framing is used.
//! Ordinary authenticated/HP interoperability still requires live validation.
use anyhow::{ensure, Result};

pub const CHUNK_BYTES: usize = 32 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = u32::MAX as u64;
pub const ITEM_INFO: u16 = 100;
pub const NEW_ITEM: u16 = 101;
pub const DATA: u16 = 102;
pub const END: u16 = 104;

pub struct Message {
    pub kind: u16,
    pub session: u32,
    pub argument: u32,
    pub payload: Vec<u8>,
}

fn message(subtype: u8, kind: u16, session: u32, argument: u32, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(session != 0, "invalid transfer ID");
    ensure!(
        data.len() <= 65498 - 18,
        "file message exceeds control record limit"
    );
    let mut out = Vec::with_capacity(18 + data.len());
    out.extend([0x22, subtype]);
    out.extend((12 + data.len() as u32).to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(kind.to_be_bytes());
    out.extend(session.to_be_bytes());
    out.extend(argument.to_be_bytes());
    out.extend(data);
    Ok(out)
}

/// A read (kind 1) or receive-file (kind 2) request; no new login is performed.
pub fn request(session: u32, path: &str, upload: bool) -> Result<Vec<u8>> {
    ensure!(path.starts_with('/'), "enter an absolute Mac path");
    ensure!(!path.as_bytes().contains(&0), "Mac path contains NUL");
    ensure!(path.len() <= 4096, "Mac path exceeds size limit");
    ensure!(
        path.split('/').all(|part| part != ".."),
        "Mac path contains parent traversal"
    );
    let mut data = 4u32.to_be_bytes().to_vec();
    data.extend((path.len() as u16).to_be_bytes());
    data.extend(path.as_bytes());
    message(2, if upload { 2 } else { 1 }, session, 1, &data)
}

pub fn upload_metadata(session: u32, name: &str, size: u64) -> Result<[Vec<u8>; 2]> {
    validate_name(name)?;
    ensure!(
        size <= MAX_FILE_BYTES,
        "native file format is limited to files below 4 GiB"
    );
    let size = size as u32;
    let mut info = [0; 48];
    info[8..12].copy_from_slice(&size.to_be_bytes());
    info[16..20].copy_from_slice(&size.to_be_bytes());
    info[24..28].copy_from_slice(&1u32.to_be_bytes());
    let mut item = vec![0; 100];
    item[42..46].copy_from_slice(&size.to_be_bytes());
    item[90..92].copy_from_slice(&0o100644u16.to_be_bytes());
    item[96..98].copy_from_slice(&(name.len() as u16).to_be_bytes());
    item.extend(name.as_bytes());
    Ok([
        message(0, ITEM_INFO, session, 1, &info)?,
        message(0, NEW_ITEM, session, 0x01000000, &item)?,
    ])
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 255,
        "file name exceeds size limit"
    );
    ensure!(name != "." && name != "..", "invalid file name");
    ensure!(
        !name
            .chars()
            .any(|c| c.is_control() || "/\\:<>\"|?*".contains(c)),
        "unsafe file name"
    );
    ensure!(!name.ends_with([' ', '.']), "unsafe file name suffix");
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    ensure!(
        !["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            && !(1..=9).any(|n| stem == format!("COM{n}") || stem == format!("LPT{n}")),
        "reserved file name"
    );
    Ok(())
}

pub fn data(session: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= CHUNK_BYTES, "file chunk exceeds limit");
    message(0, DATA, session, bytes.len() as u32, bytes)
}

pub fn end(session: u32) -> Result<Vec<u8>> {
    message(0, END, session, 0, &[])
}

impl Message {
    /// Only the known single-file/data-fork size fields are interpreted.
    pub fn announced_size(&self) -> Result<Option<u64>> {
        let field = match self.kind {
            ITEM_INFO => {
                ensure!(self.payload.len() == 48, "unsupported file-info layout");
                let count = u32::from_be_bytes(self.payload[24..28].try_into()?);
                ensure!(count == 1, "only one regular file can be received");
                ensure!(
                    self.payload[8..12] == self.payload[16..20],
                    "file sizes disagree"
                );
                Some(&self.payload[8..12])
            }
            NEW_ITEM => {
                ensure!(self.payload.len() >= 100, "truncated file metadata");
                let mode = u16::from_be_bytes(self.payload[90..92].try_into()?);
                ensure!(
                    mode & 0o170000 == 0o100000,
                    "only regular files can be received"
                );
                let len = u16::from_be_bytes(self.payload[96..98].try_into()?) as usize;
                ensure!(100 + len == self.payload.len(), "invalid file-name length");
                validate_name(std::str::from_utf8(&self.payload[100..])?)?;
                Some(&self.payload[42..46])
            }
            _ => None,
        };
        field
            .map(|b| Ok(u32::from_be_bytes(b.try_into()?) as u64))
            .transpose()
    }
}

/// Reassembles length-delimited 0x22 messages across authenticated records.
/// Returns other control data intact for the existing metadata/layout parser.
#[derive(Default)]
pub struct Decoder {
    pending: Vec<u8>,
}
impl Decoder {
    pub fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }
    pub fn feed(&mut self, body: &[u8]) -> Result<(Vec<Message>, Option<Vec<u8>>)> {
        if self.pending.is_empty() && body.first() != Some(&0x22) {
            return Ok((vec![], Some(body.to_vec())));
        }
        ensure!(
            self.pending.len() + body.len() <= MAX_MESSAGE_BYTES + 65520,
            "file message backlog too large"
        );
        self.pending.extend(body);
        let mut messages = vec![];
        let mut used = 0;
        loop {
            let rest = &self.pending[used..];
            if rest.is_empty() {
                self.pending.clear();
                return Ok((messages, None));
            }
            if rest[0] != 0x22 {
                let other = rest.to_vec();
                self.pending.clear();
                return Ok((messages, Some(other)));
            }
            if rest.len() < 6 {
                break;
            }
            ensure!(
                [0, 2].contains(&rest[1]),
                "unsupported file message subtype"
            );
            let len = u32::from_be_bytes(rest[2..6].try_into()?) as usize;
            ensure!(
                (12..=MAX_MESSAGE_BYTES - 6).contains(&len),
                "invalid file message length"
            );
            if rest.len() < 6 + len {
                break;
            }
            ensure!(
                u16::from_be_bytes(rest[6..8].try_into()?) == 1,
                "unsupported file message version"
            );
            messages.push(Message {
                kind: u16::from_be_bytes(rest[8..10].try_into()?),
                session: u32::from_be_bytes(rest[10..14].try_into()?),
                argument: u32::from_be_bytes(rest[14..18].try_into()?),
                payload: rest[18..6 + len].to_vec(),
            });
            used += 6 + len;
        }
        self.pending.drain(..used);
        Ok((messages, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_independent_native_wire_fixture() {
        // Synthetic path; expected fields transcribed independently of encoder.
        let mut expected = vec![
            0x22, 2, 0, 0, 0, 24, 0, 1, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 6,
        ];
        expected.extend(b"/a.txt");
        assert_eq!(request(2, "/a.txt", false).unwrap(), expected);
    }

    #[test]
    fn fragmented_messages_preserve_data_and_following_control() {
        let bytes = [
            data(3, &[0, 0x22, 255, 42]).unwrap(),
            end(3).unwrap(),
            vec![0x14, 0, 0, 4],
        ]
        .concat();
        for split in 1..bytes.len() - 4 {
            let mut decoder = Decoder::default();
            let (mut first, other) = decoder.feed(&bytes[..split]).unwrap();
            assert!(other.is_none());
            let (second, other) = decoder.feed(&bytes[split..]).unwrap();
            first.extend(second);
            assert_eq!(first.len(), 2);
            assert_eq!(first[0].payload, [0, 0x22, 255, 42]);
            assert_eq!(first[1].kind, END);
            assert_eq!(other.unwrap(), [0x14, 0, 0, 4]);
            assert!(!decoder.is_pending());
        }
    }

    #[test]
    fn encrypted_records_reassemble_files_and_preserve_control_data() {
        use crate::{
            control_io::Outbound,
            record::{self, RecordLayer},
        };
        let payload: Vec<u8> = (0..CHUNK_BYTES).map(|i| i as u8).collect();
        let body = [
            data(9, &payload).unwrap(),
            end(9).unwrap(),
            vec![0x14, 0, 0, 4],
        ]
        .concat();
        let mut sender = RecordLayer::new([0x45; 16], [0x67; 16]);
        let mut receiver = RecordLayer::new([0x45; 16], [0x67; 16]);
        let mut out = Outbound::default();
        // Split the logical header and payload across authenticated records.
        for part in [&body[..5], &body[5..1024], &body[1024..]] {
            out.push(sender.encrypt(part).unwrap()).unwrap();
        }
        let mut wire = vec![];
        out.flush(&mut wire).unwrap();
        assert_eq!(out.bytes(), 0);
        let mut pending = vec![];
        let mut decoder = Decoder::default();
        let mut files = vec![];
        let mut controls = vec![];
        for fragment in wire.chunks(7) {
            pending.extend(fragment);
            for record in record::drain_records(&mut receiver, &mut pending).unwrap() {
                let (messages, other) = decoder.feed(&record).unwrap();
                files.extend(messages);
                if let Some(other) = other {
                    controls.push(other);
                }
            }
        }
        assert!(pending.is_empty());
        assert!(!decoder.is_pending());
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].session, 9);
        assert_eq!(files[0].payload, payload);
        assert_eq!(files[1].kind, END);
        assert_eq!(controls, [vec![0x14, 0, 0, 4]]);
    }

    #[test]
    fn metadata_roundtrip_and_regular_file_only() {
        let encoded = upload_metadata(8, "测试.bin", 1234).unwrap();
        let mut decoder = Decoder::default();
        for bytes in encoded {
            let (mut messages, _) = decoder.feed(&bytes).unwrap();
            assert_eq!(messages[0].announced_size().unwrap(), Some(1234));
            if messages[0].kind == NEW_ITEM {
                messages[0].payload[90..92].copy_from_slice(&0o120777u16.to_be_bytes());
                assert!(messages[0].announced_size().is_err());
            }
        }
        assert!(upload_metadata(2, "large", MAX_FILE_BYTES + 1).is_err());
    }

    #[test]
    fn rejects_untrusted_lengths_paths_and_names() {
        for bytes in [
            vec![0x22, 0, 0, 0, 0, 11],
            vec![0x22, 0, 255, 255, 255, 255],
        ] {
            assert!(Decoder::default().feed(&bytes).is_err());
        }
        for path in ["relative", "/a/../b", "/a\0b"] {
            assert!(request(2, path, false).is_err());
        }
        for name in ["../x", "NUL.txt", "COM1", "a/b", "a\\b", "a:", "x."] {
            assert!(validate_name(name).is_err());
        }
    }
}
