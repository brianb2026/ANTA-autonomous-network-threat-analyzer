"""Render the ANTA app icon (PNG, Windows .ico, macOS .icns) with Pillow.

  python packaging/make_icons.py   ->  packaging/icons/anta.{png,ico,icns}
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "icons")


def render(size: int = 1024) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # Rounded-square tile with a subtle vertical gradient (macOS-style margins).
    margin = int(s * 0.09)
    tile = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    top, bottom = (24, 34, 52), (10, 14, 22)
    grad = Image.new("RGBA", (1, s))  # one column, stretched below
    for y in range(s):
        t = y / (s - 1)
        grad.putpixel((0, y), tuple(int(top[i] * (1 - t) + bottom[i] * t) for i in range(3)) + (255,))
    grad = grad.resize((s, s))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([margin, margin, s - margin, s - margin], radius=int(s * 0.2), fill=255)
    tile.paste(grad, (0, 0), mask)

    # Soft shadow under the tile.
    shadow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle([margin, margin + s * 0.015, s - margin, s - margin + s * 0.015],
                                             radius=int(s * 0.2), fill=(0, 0, 0, 120))
    img = Image.alpha_composite(img, shadow.filter(ImageFilter.GaussianBlur(s * 0.02)))
    img = Image.alpha_composite(img, tile)

    d = ImageDraw.Draw(img)
    c = s / 2
    blue, light = (57, 135, 229, 255), (134, 182, 239, 255)
    # Outer diamond ring (filled outer minus filled inner gives clean mitred corners).
    def diamond(r):
        return [(c, c - r), (c + r, c), (c, c + r), (c - r, c)]
    d.polygon(diamond(s * 0.27), fill=light)
    d.polygon(diamond(s * 0.27 - s * 0.06), fill=(17, 24, 37, 255))
    d.polygon(diamond(s * 0.115), fill=blue)
    # Beacon pulses to the right of the mark, inside the tile.
    for i, k in enumerate((0.315, 0.345, 0.375)):
        x = c + s * k
        h = s * (0.06 - i * 0.015)
        d.rounded_rectangle([x - s * 0.008, c - h, x + s * 0.008, c + h], radius=int(s * 0.008),
                            fill=(235, 104, 52, 255 - i * 70))
    return img


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    base = render(1024)
    base.save(os.path.join(OUT, "anta.png"))
    base.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "anta-256.png"))
    base.save(os.path.join(OUT, "anta.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128),
                                                     (256, 256)])
    if sys.platform == "darwin" and shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "anta.iconset")
            os.makedirs(iconset)
            for px in (16, 32, 128, 256, 512):
                base.resize((px, px), Image.LANCZOS).save(os.path.join(iconset, f"icon_{px}x{px}.png"))
                base.resize((px * 2, px * 2), Image.LANCZOS).save(os.path.join(iconset, f"icon_{px}x{px}@2x.png"))
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(OUT, "anta.icns")], check=True)
    print(f"icons written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
