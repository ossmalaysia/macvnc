"""Regenerate the original MacVNC icon with Pillow (development only)."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).parent
scale = 4
image = Image.new("RGBA", (256 * scale, 256 * scale))
draw = ImageDraw.Draw(image)
def box(coords):
    return tuple(int(v * scale) for v in coords)
draw.rounded_rectangle(box((8, 8, 248, 248)), radius=52 * scale, fill="#142D36")
draw.rounded_rectangle(box((43, 53, 213, 176)), radius=17 * scale,
                       outline="#78E3C0", width=12 * scale)
draw.line([(v[0] * scale, v[1] * scale) for v in
           [(79, 142), (79, 92), (128, 129), (177, 92), (177, 142)]],
          fill="#F3FAF8", width=11 * scale, joint="curve")
draw.rounded_rectangle(box((119, 179, 137, 198)), radius=3 * scale, fill="#78E3C0")
draw.rounded_rectangle(box((92, 195, 164, 207)), radius=6 * scale, fill="#78E3C0")
image = image.resize((256, 256), Image.Resampling.LANCZOS)
image.save(root / "macvnc.png")
image.save(root / "macvnc.ico", sizes=[(16, 16), (24, 24), (32, 32),
                                    (48, 48), (64, 64), (128, 128), (256, 256)])
