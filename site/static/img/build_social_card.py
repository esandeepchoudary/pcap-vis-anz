"""Generate site/static/img/social-card.jpg (1200x630 Open Graph image).

Colors and node-graph motif are drawn directly from the app's own dark
GitHub-style theme (static/css/style.css's :root variables), not invented
branding. Kept as a script (not just the output image) so the card can be
regenerated if the theme colors ever change.

Run from the repo root: python3 site/static/img/build_social_card.py
"""
import random
from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630

# Pulled verbatim from static/css/style.css's :root (dark theme) block.
BG = "#0d1117"
BG2 = "#161b22"
BORDER = "#30363d"
TEXT = "#e6edf3"
TEXT2 = "#8b949e"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
YELLOW = "#d29922"
PURPLE = "#bc8cff"
TEAL = "#39d353"

NODE_COLORS = [ACCENT, GREEN, YELLOW, PURPLE, TEAL, RED]

FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

random.seed(7)  # deterministic layout across regenerations

img = Image.new("RGB", (W, H), BG)
draw = ImageDraw.Draw(img)

# ── Background network-graph motif (right two-thirds), faint ──
nodes = []
for _ in range(22):
    x = random.randint(560, W - 60)
    y = random.randint(40, H - 40)
    r = random.randint(3, 9)
    nodes.append((x, y, r))

for i, (x1, y1, _) in enumerate(nodes):
    for x2, y2, _ in nodes[i + 1:]:
        if (x1 - x2) ** 2 + (y1 - y2) ** 2 < 220 ** 2 and random.random() < 0.35:
            draw.line([(x1, y1), (x2, y2)], fill=BORDER, width=1)

for x, y, r in nodes:
    color = random.choice(NODE_COLORS)
    draw.ellipse([x - r, y - r, x + r, y + r], fill=color)

# ── Left panel scrim so text stays legible over the graph ──
scrim = Image.new("RGBA", (W, H), (0, 0, 0, 0))
scrim_draw = ImageDraw.Draw(scrim)
for i in range(700):
    alpha = int(255 * (1 - i / 700))
    scrim_draw.line([(i, 0), (i, H)], fill=(13, 17, 23, alpha))
img.paste(Image.alpha_composite(img.convert("RGBA"), scrim).convert("RGB"), (0, 0))
draw = ImageDraw.Draw(img)

# ── Text ──
title_font = ImageFont.truetype(FONT_BOLD, 64)
tagline_font = ImageFont.truetype(FONT_REG, 30)
badge_font = ImageFont.truetype(FONT_MONO, 22)

margin = 70
draw.text((margin, 210), "PCAP Network", font=title_font, fill=TEXT)
draw.text((margin, 285), "Visualizer", font=title_font, fill=ACCENT)
draw.text((margin, 380), "Visualize, classify, and audit network packet captures",
          font=tagline_font, fill=TEXT2)

# Small protocol/feature badges, GitHub-label style
badges = ["OT/ICS", "IoT", "VLAN", "Anomalies"]
bx = margin
by = 440
for label in badges:
    tw = draw.textlength(label, font=badge_font)
    pad = 14
    draw.rounded_rectangle([bx, by, bx + tw + pad * 2, by + 40], radius=8, outline=BORDER, width=1, fill=BG2)
    draw.text((bx + pad, by + 8), label, font=badge_font, fill=TEXT2)
    bx += tw + pad * 2 + 14

img.save(__file__.rsplit("/", 1)[0] + "/social-card.jpg", quality=90)
print("wrote", __file__.rsplit("/", 1)[0] + "/social-card.jpg")
