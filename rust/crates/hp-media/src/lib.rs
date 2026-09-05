//! Native Apple HP media. No desktop bytes or key material are logged.
mod compositor;
mod decoder;
mod depacketize;
mod srtp;
pub use compositor::*;
pub use decoder::*;
pub use depacketize::*;
pub use srtp::*;

#[derive(Clone)]
pub struct RgbaFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

const MAX_FRAME_DIMENSION: u32 = 16_384;
const MAX_FRAME_PIXELS: u64 = 32 * 1024 * 1024;
fn rgba_len(width: u32, height: u32) -> anyhow::Result<usize> {
    if width == 0 || height == 0 || width > MAX_FRAME_DIMENSION || height > MAX_FRAME_DIMENSION {
        anyhow::bail!("Invalid framebuffer dimensions")
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_FRAME_PIXELS {
        anyhow::bail!("Framebuffer exceeds pixel limit")
    }
    usize::try_from(pixels * 4)
        .map_err(|_| anyhow::anyhow!("Framebuffer size exceeds address space"))
}
fn allocate_rgba(width: u32, height: u32) -> anyhow::Result<Vec<u8>> {
    let length = rgba_len(width, height)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(length)
        .map_err(|_| anyhow::anyhow!("Framebuffer allocation failed"))?;
    pixels.resize(length, 0);
    Ok(pixels)
}
