use anyhow::{bail, ensure, Result};
use std::{
    collections::VecDeque,
    io::{ErrorKind, Write},
    time::{Duration, Instant},
};

/// Ciphertext stays in wire order, including partially written records.
#[derive(Default)]
pub(crate) struct Outbound {
    records: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    stalled_since: Option<Instant>,
}
impl Outbound {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn push(&mut self, wire: Vec<u8>) -> Result<()> {
        ensure!(
            self.bytes + wire.len() <= 512 * 1024,
            "control output backlog exceeded limit"
        );
        self.bytes += wire.len();
        self.records.push_back(wire);
        Ok(())
    }
    pub fn flush(&mut self, writer: &mut impl Write) -> Result<()> {
        let mut budget = 64 * 1024;
        let mut attempts = 128;
        while let Some(record) = self.records.front() {
            if attempts == 0 {
                break;
            }
            attempts -= 1;
            let n = match writer
                .write(&record[self.offset..][..budget.min(record.len() - self.offset)])
            {
                Ok(0) => bail!("Mac closed the HP control writer"),
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let began = self.stalled_since.get_or_insert_with(Instant::now);
                    ensure!(
                        began.elapsed() < Duration::from_secs(3),
                        "HP control writer stalled"
                    );
                    return Ok(());
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            self.stalled_since = None;
            self.offset += n;
            self.bytes -= n;
            budget -= n;
            if self.offset == record.len() {
                self.records.pop_front();
                self.offset = 0;
            }
            if budget == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Partial {
        bytes: Vec<u8>,
        block: bool,
    }
    impl Write for Partial {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.block = !self.block;
            if self.block {
                return Err(ErrorKind::WouldBlock.into());
            }
            let n = 3.min(b.len());
            self.bytes.extend(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn partial_writes_and_backpressure_preserve_record_order() {
        let mut out = Outbound::default();
        out.push(b"first record".to_vec()).unwrap();
        out.push(b"second".to_vec()).unwrap();
        let mut writer = Partial {
            bytes: vec![],
            block: false,
        };
        for _ in 0..20 {
            out.flush(&mut writer).unwrap();
        }
        assert_eq!(writer.bytes, b"first recordsecond");
        assert_eq!(out.bytes(), 0);
    }
    #[test]
    fn full_queue_keeps_existing_bytes() {
        let mut out = Outbound::default();
        out.push(vec![1; 512 * 1024]).unwrap();
        assert!(out.push(vec![2]).is_err());
        assert_eq!(out.bytes(), 512 * 1024);
    }
    #[test]
    fn interrupted_writer_yields_without_losing_bytes() {
        struct Interrupted(usize);
        impl Write for Interrupted {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.0 += 1;
                Err(ErrorKind::Interrupted.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Outbound::default();
        out.push(b"pending".to_vec()).unwrap();
        let mut writer = Interrupted(0);
        out.flush(&mut writer).unwrap();
        assert_eq!(writer.0, 128);
        assert_eq!(out.bytes(), 7);
        let mut bytes = vec![];
        out.flush(&mut bytes).unwrap();
        assert_eq!(bytes, b"pending");
    }
}
