#!/usr/bin/env python3
"""
Génère assets/tnb_flow.gif : animation expliquant le TNB.

Pile (bas -> haut) : TNB (outil) -> Hardware -> SEAPATH -> {ABB, Schneider}.
Phase 1 : des SV montent du TNB jusqu'aux deux vIED (ABB rouge, Schneider vert).
Phase 2 : les GOOSE de trip redescendent des vIED jusqu'au TNB.
La boucle illustre la mesure de latence (aller SV -> retour trip).

Pur Python (aucune dépendance) : rendu en buffer indexé + encodeur GIF89a/LZW.
"""
import math

W, H = 500, 600
NDOTS = 4

# ---------------------------------------------------------------- palette (16)
PAL = [
    (26, 27, 38),    # 0 fond
    (36, 40, 59),    # 1 surface (remplissage des boîtes)
    (192, 202, 245), # 2 texte clair
    (122, 162, 247), # 3 accent / SV
    (86, 95, 137),   # 4 muted / connecteurs
    (232, 65, 60),   # 5 ABB rouge
    (55, 178, 77),   # 6 Schneider vert
    (157, 124, 216), # 7 SEAPATH violet
    (140, 148, 175), # 8 Hardware gris
    (245, 166, 35),  # 9 GOOSE trip orange
    (255, 255, 255), # 10 blanc
    (14, 15, 22),    # 11 bordure sombre
    (70, 90, 130),   # 12 traînée SV
    (130, 100, 45),  # 13 traînée trip
    (250, 120, 116), # 14 rouge clair (glow)
    (120, 230, 150), # 15 vert clair (glow)
]

# ---------------------------------------------------------------- police 5x7
F = {
    "A": ["01110","10001","10001","11111","10001","10001","10001"],
    "B": ["11110","10001","10001","11110","10001","10001","11110"],
    "C": ["01111","10000","10000","10000","10000","10000","01111"],
    "D": ["11110","10001","10001","10001","10001","10001","11110"],
    "E": ["11111","10000","10000","11110","10000","10000","11111"],
    "G": ["01111","10000","10000","10111","10001","10001","01111"],
    "H": ["10001","10001","10001","11111","10001","10001","10001"],
    "I": ["11111","00100","00100","00100","00100","00100","11111"],
    "L": ["10000","10000","10000","10000","10000","10000","11111"],
    "N": ["10001","11001","10101","10101","10101","10011","10001"],
    "O": ["01110","10001","10001","10001","10001","10001","01110"],
    "P": ["11110","10001","10001","11110","10000","10000","10000"],
    "R": ["11110","10001","10001","11110","10100","10010","10001"],
    "S": ["01111","10000","10000","01110","00001","00001","11110"],
    "T": ["11111","00100","00100","00100","00100","00100","00100"],
    "U": ["10001","10001","10001","10001","10001","10001","01110"],
    "V": ["10001","10001","10001","10001","10001","01010","00100"],
    "W": ["10001","10001","10001","10101","10101","10101","01010"],
    " ": ["00000"]*7,
    "-": ["00000","00000","00000","01110","00000","00000","00000"],
    ":": ["00000","00100","00100","00000","00100","00100","00000"],
}


class Canvas:
    def __init__(self, w, h, bg=0):
        self.w, self.h = w, h
        self.px = bytearray([bg]) * (w * h)

    def put(self, x, y, c):
        if 0 <= x < self.w and 0 <= y < self.h:
            self.px[y * self.w + x] = c

    def fill_rect(self, x0, y0, x1, y1, c):
        for y in range(max(0, y0), min(self.h, y1)):
            row = y * self.w
            for x in range(max(0, x0), min(self.w, x1)):
                self.px[row + x] = c

    def rect_border(self, x0, y0, x1, y1, c, t=2):
        self.fill_rect(x0, y0, x1, y0 + t, c)
        self.fill_rect(x0, y1 - t, x1, y1, c)
        self.fill_rect(x0, y0, x0 + t, y1, c)
        self.fill_rect(x1 - t, y0, x1, y1, c)

    def disc(self, cx, cy, r, c):
        for y in range(-r, r + 1):
            for x in range(-r, r + 1):
                if x * x + y * y <= r * r:
                    self.put(cx + x, cy + y, c)

    def line(self, x0, y0, x1, y1, c, t=1):
        x0, y0, x1, y1 = int(x0), int(y0), int(x1), int(y1)
        dx, dy = abs(x1 - x0), abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        while True:
            for ox in range(t):
                for oy in range(t):
                    self.put(x0 + ox, y0 + oy, c)
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy; x0 += sx
            if e2 < dx:
                err += dx; y0 += sy

    def text(self, cx, cy, s, c, scale=2, center=True):
        s = s.upper()
        gw = (5 + 1) * scale
        total = len(s) * gw - scale
        x = cx - total // 2 if center else cx
        y = cy - (7 * scale) // 2
        for ch in s:
            g = F.get(ch, F[" "])
            for ry, row in enumerate(g):
                for rx, p in enumerate(row):
                    if p == "1":
                        self.fill_rect(x + rx * scale, y + ry * scale,
                                       x + rx * scale + scale, y + ry * scale + scale, c)
            x += gw


# ---------------------------------------------------------------- géométrie
CX = 250
ABB = (140, 110); SE = (360, 110)
SEA = (250, 250); HW = (250, 370); TNB = (250, 500)

BOXES = [
    # (x0,y0,x1,y1, border_color, lines[(text,scale)])
    (65, 75, 215, 145, 5, [("ABB", 3)]),
    (268, 75, 452, 145, 6, [("SCHNEIDER", 2), ("ELECTRIC", 2)]),
    (130, 216, 370, 284, 7, [("SEAPATH", 2)]),
    (130, 336, 370, 404, 8, [("HARDWARE", 2)]),
    (85, 462, 415, 538, 3, [("TNB", 3), ("OUTIL DE TEST", 2)]),
]

PATH_SV = {"abb": [TNB, HW, SEA, ABB], "se": [TNB, HW, SEA, SE]}
PATH_GO = {"abb": [ABB, SEA, HW, TNB], "se": [SE, SEA, HW, TNB]}


def point_at(path, t):
    segs = []
    tot = 0.0
    for i in range(len(path) - 1):
        (x0, y0), (x1, y1) = path[i], path[i + 1]
        d = math.hypot(x1 - x0, y1 - y0)
        segs.append((path[i], path[i + 1], d)); tot += d
    d = t * tot
    for (x0, y0), (x1, y1), seg in segs:
        if d <= seg or seg == 0:
            f = (d / seg) if seg else 0
            return (x0 + (x1 - x0) * f, y0 + (y1 - y0) * f)
        d -= seg
    return path[-1]


def draw_static(cv, highlight_top=False, highlight_tnb=False):
    cv.fill_rect(0, 0, W, H, 0)
    # titre + légende
    cv.text(CX, 34, "TNB  -  SV  VERS  TRIP  GOOSE", 2, scale=2)
    cv.disc(70, 568, 5, 3); cv.text(118, 568, "SV", 2, scale=2, center=True)
    cv.disc(250, 568, 5, 9); cv.text(355, 568, "GOOSE TRIP", 2, scale=2, center=True)
    # connecteurs (sous les boîtes)
    for p in (PATH_SV["abb"], PATH_SV["se"]):
        for i in range(len(p) - 1):
            cv.line(p[i][0], p[i][1], p[i + 1][0], p[i + 1][1], 4, t=2)
    # boîtes
    for (x0, y0, x1, y1, bc, lines) in BOXES:
        cv.fill_rect(x0, y0, x1, y1, 1)
        bcol = bc
        tck = 3
        if highlight_top and bc in (5, 6):
            bcol = 14 if bc == 5 else 15; tck = 4
        if highlight_tnb and bc == 3:
            bcol = 10; tck = 4
        cv.rect_border(x0, y0, x1, y1, bcol, t=tck)
        n = len(lines)
        cyc = (y0 + y1) // 2
        for i, (txt, sc) in enumerate(lines):
            yy = cyc + (i - (n - 1) / 2) * (8 * sc + 2)
            cv.text((x0 + x1) // 2, int(yy), txt, 2, scale=sc)


def frame(idx, nsv, ngo):
    total = nsv + ngo
    if idx < nsv:
        u = idx / nsv
        cv = Canvas(W, H)
        draw_static(cv, highlight_top=(u > 0.72))
        for key in ("abb", "se"):
            for k in range(NDOTS):
                t = (u + k / NDOTS) % 1.0
                x, y = point_at(PATH_SV[key], t)
                cv.disc(int(x), int(y), 3, 12)
                cv.disc(int(x), int(y), 2, 3)
    else:
        v = (idx - nsv) / ngo
        cv = Canvas(W, H)
        draw_static(cv, highlight_tnb=(v > 0.72))
        for key in ("abb", "se"):
            for k in range(NDOTS):
                t = (v + k / NDOTS) % 1.0
                x, y = point_at(PATH_GO[key], t)
                cv.disc(int(x), int(y), 3, 13)
                cv.disc(int(x), int(y), 2, 9)
    return cv.px


# ---------------------------------------------------------------- GIF/LZW
class BitW:
    def __init__(self):
        self.acc = 0; self.nb = 0; self.buf = bytearray()

    def write(self, code, size):
        self.acc |= code << self.nb; self.nb += size
        while self.nb >= 8:
            self.buf.append(self.acc & 0xFF); self.acc >>= 8; self.nb -= 8

    def flush(self):
        if self.nb > 0:
            self.buf.append(self.acc & 0xFF); self.acc = 0; self.nb = 0
        return bytes(self.buf)


def lzw(indices, mcs):
    """LZW GIF à LARGEUR DE CODE FIXE (mcs+1 bits).

    On n'augmente jamais la taille de code : dès que la table est pleine pour
    cette largeur (next == 2^(mcs+1)), on émet un code Clear et on repart. Cela
    élimine toute la logique d'agrandissement de code (la source n°1 de GIF
    invalides) ; tout décodeur standard lit ce flux sans ambiguïté."""
    clear = 1 << mcs
    eoi = clear + 1
    size = mcs + 1
    cap = 1 << size            # tous les codes restent < cap (largeur fixe)
    out = BitW()
    out.write(clear, size)

    def fresh():
        return {(i,): i for i in range(clear)}, clear + 2

    table, nxt = fresh()
    pat = ()
    for idx in indices:
        np = pat + (idx,)
        if np in table:
            pat = np
        else:
            out.write(table[pat], size)
            if nxt < cap:
                table[np] = nxt; nxt += 1
            else:
                out.write(clear, size)          # table pleine -> réinitialise
                table, nxt = fresh()
            pat = (idx,)
    out.write(table[pat], size)
    out.write(eoi, size)
    return out.flush()


def sub_blocks(data):
    out = bytearray()
    i = 0
    while i < len(data):
        chunk = data[i:i + 255]
        out.append(len(chunk)); out += chunk; i += 255
    out.append(0)
    return bytes(out)


def write_gif(path, frames, delay_cs):
    mcs = 4  # 16 couleurs
    with open(path, "wb") as f:
        f.write(b"GIF89a")
        f.write(bytes([W & 0xFF, W >> 8, H & 0xFF, H >> 8]))
        f.write(bytes([0xF0 | (mcs - 1), 0, 0]))  # table globale, 2^4 couleurs
        for (r, g, b) in PAL:
            f.write(bytes([r, g, b]))
        # boucle infinie (NETSCAPE2.0)
        f.write(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00")
        for px in frames:
            f.write(bytes([0x21, 0xF9, 0x04, 0x04,
                           delay_cs & 0xFF, delay_cs >> 8, 0x00, 0x00]))
            f.write(b"\x2C")
            f.write(bytes([0, 0, 0, 0, W & 0xFF, W >> 8, H & 0xFF, H >> 8, 0]))
            f.write(bytes([mcs]))
            f.write(sub_blocks(lzw(px, mcs)))
        f.write(b"\x3B")


def main():
    nsv, ngo = 18, 18
    delay = 6  # centisecondes -> 60 ms/frame (boucle ~2,2 s)
    frames = [frame(i, nsv, ngo) for i in range(nsv + ngo)]
    import os
    out = os.path.join(os.path.dirname(__file__), "tnb_flow.gif")
    write_gif(out, frames, delay)
    print("écrit:", out, "(", os.path.getsize(out), "octets,", len(frames), "frames )")


if __name__ == "__main__":
    main()
