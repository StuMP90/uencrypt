"""Generates the app icon and MSIX logo assets from code (no binary design source to maintain).

Usage: python3 tools/make_icons.py   (requires Pillow)
"""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
BG = (33, 37, 43, 255)
ACCENT = (79, 157, 222, 255)
FG = (230, 230, 230, 255)
SCALE = 4  # draw large and shrink, for smooth edges at small sizes


def glyph(size: int, pad_ratio: float = 0.0, transparent: bool = False) -> Image.Image:
    big = size * SCALE
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = int(big * pad_ratio)
    inner = big - 2 * pad
    if not transparent:
        d.rounded_rectangle((pad, pad, big - pad - 1, big - pad - 1), radius=inner // 5, fill=BG)

    def p(x: float, y: float) -> tuple[float, float]:
        return pad + inner * x, pad + inner * y

    # Shackle: a "u" upside down, in the accent colour.
    stroke = inner * 0.085
    (x0, y0), (x1, y1) = p(0.33, 0.17), p(0.67, 0.51)
    d.arc((x0, y0, x1, y1), 180, 360, fill=ACCENT, width=int(stroke))
    d.rectangle((x0, (y0 + y1) / 2, x0 + stroke, p(0, 0.50)[1]), fill=ACCENT)
    d.rectangle((x1 - stroke, (y0 + y1) / 2, x1, p(0, 0.50)[1]), fill=ACCENT)
    # Body.
    bx0, by0 = p(0.24, 0.45)
    bx1, by1 = p(0.76, 0.83)
    d.rounded_rectangle((bx0, by0, bx1, by1), radius=inner * 0.07, fill=FG)
    # Keyhole.
    cx, cy = p(0.5, 0.60)
    r = inner * 0.05
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=BG)
    d.polygon([(cx - r * 0.55, cy), (cx + r * 0.55, cy), (cx + r * 0.8, p(0, 0.73)[1]), (cx - r * 0.8, p(0, 0.73)[1])], fill=BG)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    build = ROOT / "gui" / "build"
    (build / "windows").mkdir(parents=True, exist_ok=True)
    glyph(1024).save(build / "appicon.png")
    glyph(256).save(build / "windows" / "icon.ico",
                    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    linux = ROOT / "packaging" / "linux"
    linux.mkdir(parents=True, exist_ok=True)
    glyph(256).save(linux / "uencrypt.png")

    msix = ROOT / "packaging" / "msix" / "Images"
    msix.mkdir(parents=True, exist_ok=True)
    glyph(50).save(msix / "StoreLogo.png")
    glyph(44).save(msix / "Square44x44Logo.png")
    glyph(44, transparent=True).save(msix / "Square44x44Logo.targetsize-44_altform-unplated.png")
    glyph(150, pad_ratio=0.18).save(msix / "Square150x150Logo.png")
    wide = Image.new("RGBA", (310, 150), BG)
    wide.alpha_composite(glyph(150, pad_ratio=0.18), (80, 0))
    wide.save(msix / "Wide310x150Logo.png")
    glyph(44, transparent=True).save(msix / "FileIcon.png")

    # Microsoft Store listing logos (Partner Center: 300x300 required, 150x150 and 71x71).
    store = ROOT / "packaging" / "store"
    store.mkdir(parents=True, exist_ok=True)
    for size in (300, 150, 71):
        glyph(size).save(store / f"StoreLogo-{size}x{size}.png")


if __name__ == "__main__":
    main()
