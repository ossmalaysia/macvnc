use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::{ensure, Result};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Apple's legacy HP control framing. Each direction chains CBC across records.
/// Authentication failures are fatal: never resynchronize counters by guessing.
pub struct RecordLayer {
    key: [u8; 16],
    enc_iv: [u8; 16],
    dec_iv: [u8; 16],
    enc_seq: u32,
    dec_seq: u32,
    failed: bool,
}
impl Drop for RecordLayer {
    fn drop(&mut self) {
        self.key.zeroize();
        self.enc_iv.zeroize();
        self.dec_iv.zeroize();
    }
}
impl RecordLayer {
    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            key,
            enc_iv: iv,
            dec_iv: iv,
            enc_seq: 0,
            dec_seq: 0,
            failed: false,
        }
    }
    pub fn encrypt(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !self.failed,
            "control record layer is unusable after a verification failure"
        );
        ensure!(self.enc_seq < u32::MAX, "record sequence exhausted");
        ensure!(body.len() <= 65498, "control message too large");
        let size = (2 + body.len() + 20 + 15) & !15;
        let mut p = Zeroizing::new(vec![0; size]);
        p[..2].copy_from_slice(&(body.len() as u16).to_be_bytes());
        p[2..2 + body.len()].copy_from_slice(body);
        let mut hash = Sha1::new();
        hash.update(self.enc_seq.to_be_bytes());
        hash.update(&p[..size - 20]);
        p[size - 20..].copy_from_slice(&hash.finalize());
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        for block in p.as_chunks_mut::<16>().0 {
            for (b, iv) in block.iter_mut().zip(self.enc_iv) {
                *b ^= iv;
            }
            cipher.encrypt_block(GenericArray::from_mut_slice(block));
            self.enc_iv.copy_from_slice(block);
        }
        self.enc_seq = self
            .enc_seq
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record sequence exhausted"))?;
        let mut out = (size as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&p);
        Ok(out)
    }
    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !self.failed,
            "control record layer is unusable after a verification failure"
        );
        ensure!(self.dec_seq < u32::MAX, "record sequence exhausted");
        ensure!(
            (32..=65520).contains(&ct.len()) && ct.len().is_multiple_of(16),
            "invalid encrypted record length"
        );
        self.failed = true;
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        let mut p = Zeroizing::new(ct.to_vec());
        for block in p.as_chunks_mut::<16>().0 {
            let mut next = [0; 16];
            next.copy_from_slice(block);
            cipher.decrypt_block(GenericArray::from_mut_slice(block));
            for (b, iv) in block.iter_mut().zip(self.dec_iv) {
                *b ^= iv;
            }
            self.dec_iv = next;
        }
        let end = p.len() - 20;
        let mut hash = Sha1::new();
        hash.update(self.dec_seq.to_be_bytes());
        hash.update(&p[..end]);
        ensure!(
            bool::from(hash.finalize().as_slice().ct_eq(&p[end..])),
            "control record authentication failed"
        );
        let len = u16::from_be_bytes([p[0], p[1]]) as usize;
        ensure!(len <= end - 2, "invalid inner record length");
        self.dec_seq = self
            .dec_seq
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record sequence exhausted"))?;
        self.failed = false;
        Ok(p[2..2 + len].to_vec())
    }
}
pub fn unwrap(key: &[u8; 16], data: &[u8]) -> Result<[u8; 16]> {
    ensure!(data.len() == 16, "invalid wrapped key block length");
    let mut out = [0; 16];
    out.copy_from_slice(data);
    Aes128::new(GenericArray::from_slice(key))
        .decrypt_block(GenericArray::from_mut_slice(&mut out));
    Ok(out)
}

pub(crate) fn drain_records(
    records: &mut RecordLayer,
    pending: &mut Vec<u8>,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut used = 0;
    while pending.len() - used >= 2 {
        let n = u16::from_be_bytes([pending[used], pending[used + 1]]) as usize;
        ensure!(
            n >= 32 && n.is_multiple_of(16),
            "invalid control record length"
        );
        if pending.len() - used < 2 + n {
            break;
        }
        out.push(records.decrypt(&pending[used + 2..used + 2 + n])?);
        used += 2 + n;
    }
    pending.drain(..used);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_wrapped_block_returns_error_without_panicking() {
        for length in [0, 15, 17, 32] {
            assert!(unwrap(&[0; 16], &vec![0; length]).is_err());
        }
    }
    #[test]
    fn integrity_failure_permanently_disables_both_directions() {
        let mut sender = RecordLayer::new([1; 16], [2; 16]);
        let mut receiver = RecordLayer::new([1; 16], [2; 16]);
        let mut corrupt = sender.encrypt(b"one").unwrap();
        corrupt[7] ^= 1;
        assert!(receiver.decrypt(&corrupt[2..]).is_err());
        let next = sender.encrypt(b"two").unwrap();
        assert!(receiver.decrypt(&next[2..]).is_err());
        assert!(receiver.encrypt(b"no reply on failed channel").is_err());
    }
    #[test]
    fn oversized_ciphertext_and_exhausted_counter_do_not_change_state() {
        let mut r = RecordLayer::new([1; 16], [2; 16]);
        assert!(r.decrypt(&vec![0; 65536]).is_err());
        assert_eq!(r.dec_iv, [2; 16]);
        r.enc_seq = u32::MAX;
        assert!(r.encrypt(b"x").is_err());
        assert_eq!(r.enc_iv, [2; 16]);
    }
    #[test]
    fn maximum_record_length_does_not_wrap() {
        let mut r = RecordLayer::new([0; 16], [0; 16]);
        assert!(r.encrypt(&vec![0; 65499]).is_err());
        let wire = r.encrypt(&vec![0; 65498]).unwrap();
        assert_eq!(
            u16::from_be_bytes([wire[0], wire[1]]) as usize,
            wire.len() - 2
        );
    }
    #[test]
    fn single_byte_record_framing() {
        let mut enc = RecordLayer::new([1; 16], [2; 16]);
        let mut dec = RecordLayer::new([1; 16], [2; 16]);
        let a = enc.encrypt(b"first").unwrap();
        let b = enc.encrypt(b"second").unwrap();
        let mut pending = Vec::new();
        let mut messages = Vec::new();
        for byte in a.into_iter().chain(b) {
            pending.push(byte);
            messages.extend(drain_records(&mut dec, &mut pending).unwrap());
        }
        assert_eq!(messages, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(pending.is_empty());
    }
    #[test]
    fn chained_records() {
        let mut a = RecordLayer::new([9; 16], [2; 16]);
        let mut b = RecordLayer::new([9; 16], [2; 16]);
        for data in [&b"hello"[..], &[42; 200][..], &[][..]] {
            let ct = a.encrypt(data).unwrap();
            assert_eq!(b.decrypt(&ct[2..]).unwrap(), data);
        }
    }
    #[test]
    fn altered_ciphertext_rejected() {
        let mut a = RecordLayer::new([9; 16], [2; 16]);
        let mut b = RecordLayer::new([9; 16], [2; 16]);
        let mut ct = a.encrypt(b"hello").unwrap();
        ct[3] ^= 1;
        assert!(b.decrypt(&ct[2..]).is_err());
    }
    #[test]
    fn ecb_nist_vector() {
        let key = [0; 16];
        let ct = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        assert_eq!(unwrap(&key, &ct).unwrap(), [0; 16]);
    }
    #[test]
    fn node_crypto_differential_fixture() {
        let mut r = RecordLayer::new([9; 16], [2; 16]);
        for (body, expected) in [
            (
                &b"hello"[..],
                "0020cb575b5f157d75e51ea3d1cb5fb3e89b599d84c51e3998f2ec3c25de074e94b9",
            ),
            (
                &b"second"[..],
                "0020cd9c7a34dd74dec8143162f025e84fdd0c475c9cb438807158c2bb973abeee85",
            ),
        ] {
            let actual: String = r
                .encrypt(body)
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }
}
