use crate::{allocate_rgba, rgba_len, DecodedTile, RgbaFrame};
use anyhow::{bail, Result};
pub struct Compositor {
    frame: RgbaFrame,
    tiles: usize,
    slot_height: Option<u32>,
    seen: Vec<bool>,
}
impl Compositor {
    pub fn new(width: u32, height: u32, tiles: usize) -> Result<Self> {
        if tiles == 0 || tiles > 16 {
            bail!("Invalid framebuffer dimensions")
        }
        Ok(Self {
            frame: RgbaFrame {
                width,
                height,
                pixels: allocate_rgba(width, height)?,
            },
            tiles,
            slot_height: None,
            seen: vec![false; tiles],
        })
    }
    pub fn push(&mut self, t: DecodedTile) -> Result<Option<RgbaFrame>> {
        Ok(self.update(t)?.then(|| self.snapshot()))
    }
    /// Apply a decoded band without cloning the full screen. Batch all ready
    /// bands, then take one snapshot per presentation interval.
    pub fn update(&mut self, t: DecodedTile) -> Result<bool> {
        if t.tile >= self.tiles || t.frame.pixels.len() != rgba_len(t.frame.width, t.frame.height)?
        {
            bail!("Invalid decoded tile")
        }
        // Apple's encoded bands have CTU padding. Preserve negotiated canvas size;
        // only the bottom band is clipped, never stretch every band equally.
        let slot = *self.slot_height.get_or_insert(t.frame.height);
        if t.frame.height != slot {
            bail!("Tile geometry changed; renegotiate stream")
        }
        let y = t.tile as u32 * slot;
        if y >= self.frame.height {
            return Ok(false);
        }
        let rows = slot.min(self.frame.height - y);
        let cols = t.frame.width.min(self.frame.width);
        for row in 0..rows {
            let src = row as usize * t.frame.width as usize * 4;
            let dst = (y + row) as usize * self.frame.width as usize * 4;
            self.frame.pixels[dst..dst + cols as usize * 4]
                .copy_from_slice(&t.frame.pixels[src..src + cols as usize * 4]);
        }
        self.seen[t.tile] = true;
        // Publish on every changed band after initial coverage; no same-timestamp
        // barrier: Apple stops transmitting unchanged bands on a static desktop.
        Ok(self.seen.iter().all(|v| *v))
    }
    pub fn snapshot(&self) -> RgbaFrame {
        self.frame.clone()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malicious_dimensions_fail_before_multiplication_or_state_change() {
        let mut c = Compositor::new(1, 1, 1).unwrap();
        for (width, height, pixels) in [
            (u32::MAX, u32::MAX, vec![]),
            (16384, 16384, vec![]),
            (1, 1, vec![0; 3]),
        ] {
            assert!(c
                .update(DecodedTile {
                    tile: 0,
                    pts: 0,
                    frame: RgbaFrame {
                        width,
                        height,
                        pixels
                    }
                })
                .is_err());
            assert!(c.slot_height.is_none());
        }
        assert!(c
            .update(DecodedTile {
                tile: 0,
                pts: 0,
                frame: RgbaFrame {
                    width: 1,
                    height: 1,
                    pixels: vec![1, 2, 3, 255]
                }
            })
            .unwrap());
        assert_eq!(c.snapshot().pixels, vec![1, 2, 3, 255]);
    }
    #[test]
    fn clips_ctu_padding_and_retains_static_bands() {
        let mut c = Compositor::new(1, 7, 2).unwrap();
        let tile = |i, v| DecodedTile {
            tile: i,
            pts: 0,
            frame: RgbaFrame {
                width: 1,
                height: 4,
                pixels: vec![v; 16],
            },
        };
        assert!(c.push(tile(0, 3)).unwrap().is_none());
        let f = c.push(tile(1, 9)).unwrap().unwrap();
        assert_eq!(f.height, 7);
        assert_eq!(f.pixels.len(), 28);
        assert_eq!(&f.pixels[16..], &[9; 12]);
        let f = c.push(tile(0, 2)).unwrap().unwrap();
        assert_eq!(&f.pixels[16..], &[9; 12]);
    }
}
