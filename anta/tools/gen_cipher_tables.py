"""Generate engine/src/cipher_tables.inc: the constant tables of the older TLS block
ciphers, read from their published specifications rather than typed in.

  python -m anta.tools.gen_cipher_tables RFC3713 RFC5794 RFC4269 DES_WIKITEXT > engine/src/cipher_tables.inc

  RFC 3713  Camellia: SBOX1 and Sigma1-6        https://www.rfc-editor.org/rfc/rfc3713.txt
  RFC 5794  ARIA: SB1-SB4 and C1-C3             https://www.rfc-editor.org/rfc/rfc5794.txt
  RFC 4269  SEED: S0, S1 and KC1-KC16           https://www.rfc-editor.org/rfc/rfc4269.txt
  DES (FIPS 46-3) tables, as the wikitext of
  https://en.wikipedia.org/wiki/DES_supplementary_material (action=raw)

Each table is checked against properties the specifications state before it is written;
the ciphers built on them are checked against the specifications' test vectors.
"""
from __future__ import annotations

import re
import sys


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i + len(start):text.index(end, i + len(start))]


def camellia(text: str):
    block = _between(text, "SBOX1:", "2.4.2.")
    rows = re.findall(r"^\s+[0-9a-f]0:((?:\s+\d+){16})\s*$", block, re.M)
    sbox = [int(v) for row in rows for v in row.split()]
    sigma = [int(v, 16) for v in re.findall(r"Sigma\d = 0x([0-9A-F]{16});", text)]
    assert len(sbox) == 256 and sorted(sbox) == list(range(256)) and sbox[0x3D] == 86, "Camellia SBOX1"
    assert len(sigma) == 6 and sigma[0] == 0xA09E667F3BCC908B, "Camellia Sigma"
    return sbox, sigma


def aria(text: str):
    boxes = []
    for name, nxt in (("SB1:", "SB2:"), ("SB2:", "SB3:"), ("SB3:", "SB4:"), ("SB4:", "For example")):
        block = _between(text, name, nxt)
        rows = re.findall(r"^\s+[0-9a-f]0((?: +[0-9a-f]{1,2}){16})\s*$", block, re.M)
        boxes.append([int(v, 16) for row in rows for v in row.split()])
    consts = [bytes.fromhex(v) for v in re.findall(r"C\d =\s+0x([0-9a-f]{32})", text)]
    sb1, sb2, sb3, sb4 = boxes
    assert all(len(b) == 256 and sorted(b) == list(range(256)) for b in boxes), "ARIA S-boxes"
    assert all(sb3[sb1[x]] == x and sb4[sb2[x]] == x for x in range(256)), "ARIA: SB3, SB4 invert SB1, SB2"
    assert sb1[0x23] == 0x26 and sb4[0xEF] == 0xD3 and len(consts) == 3, "ARIA examples"
    return boxes, consts


def seed(text: str):
    def box(name, nxt):
        return [int(v, 16) for v in re.findall(r"\b([0-9A-F]{2})\b", _between(text, name, nxt))]
    s0 = box("- S-Box S0", "- S-Box S1")
    s1 = box("- S-Box S1", "A.2.")
    kc = [int(v, 16) for v in re.findall(r"KC\d+\s+\|\s+0x([0-9A-F]{8})", text)]
    kc = [kc[i] for i in sorted(range(len(kc)), key=lambda i: int(re.findall(r"KC(\d+)\s+\|", text)[i]))]
    assert len(s0) == 256 and len(s1) == 256 and sorted(s0) == sorted(s1) == list(range(256)), "SEED S-boxes"
    # SS0[0] in Appendix A.2 is S0[0] masked with m3, m2, m1, m0 (0x3F, 0xCF, 0xF3, 0xFC).
    first = re.search(r"- S-Box SS0\s+([0-9A-F]{8})", text).group(1)
    v = s0[0]
    assert first == f"{v & 0x3F:02X}{v & 0xCF:02X}{v & 0xF3:02X}{v & 0xFC:02X}", "SEED SS0 from S0"
    assert len(kc) == 16 and kc[0] == 0x9E3779B9, "SEED KC"
    return s0, s1, kc


def des(text: str):
    def table(heading, count):
        block = text[text.index(heading):]
        block = block[:block.index("\n==", 1)]  # (to the next section: PC-1 is printed as two halves)
        vals = [int(v) for row in re.findall(r"^\|(\d+(?:\|\|\d+)+)\s*$", block, re.M) for v in row.split("||")]
        assert len(vals) == count, (heading, len(vals))
        return vals
    ip, fp = table("==Initial permutation", 64), table("==Final permutation", 64)
    e, p = table("==Expansion function", 48), table("==Permutation (P)", 32)
    pc1, pc2 = table("==Permuted choice 1", 56), table("==Permuted choice 2", 48)
    sblock = text[text.index("==Substitution boxes"):text.index("==Key Generation")]
    svals = [int(v) for row in re.findall(r"^\|(\d+(?:\|\|\d+){15})\s*$", sblock, re.M) for v in row.split("||")]
    assert len(svals) == 8 * 64 and all(0 <= v < 16 for v in svals), "DES S-boxes"
    sboxes = [svals[i * 64:(i + 1) * 64] for i in range(8)]
    assert all(sorted(sb[r * 16:(r + 1) * 16]) == list(range(16)) for sb in sboxes for r in range(4)), "DES S rows"
    rot = text[text.index("=== Bits Rotation"):text.index("=== Key Compression")]
    left = rot[rot.index("Number of Left rotations"):]
    shifts = [int(v) for v in re.findall(r"^\|(\d)\s*$", left, re.M)][:16]
    assert len(shifts) == 16 and sum(shifts) == 28, "DES rotations"
    assert all(fp[ip[i] - 1] == i + 1 for i in range(64)), "DES IP and IP^-1"
    return ip, fp, e, p, pc1, pc2, shifts, sboxes


def c_array(ctype: str, name: str, values, fmt="{}", per_line=16) -> str:
    items = [fmt.format(v) for v in values]
    lines = [", ".join(items[i:i + per_line]) for i in range(0, len(items), per_line)]
    return f"const {ctype} {name}[{len(items)}] = {{\n    " + ",\n    ".join(lines) + "};\n"


def main(argv: list[str]) -> str:
    if len(argv) != 4:
        sys.exit(__doc__)
    cam_text, aria_text, seed_text, des_text = (open(p, encoding="utf-8").read() for p in argv)
    sbox, sigma = camellia(cam_text)
    (sb1, sb2, sb3, sb4), consts = aria(aria_text)
    s0, s1, kc = seed(seed_text)
    ip, fp, e, p, pc1, pc2, shifts, sboxes = des(des_text)
    out = ["// Generated by anta/tools/gen_cipher_tables.py from RFC 3713 (Camellia), RFC 5794 (ARIA),",
           "// RFC 4269 (SEED) and the FIPS 46-3 DES tables. Do not edit by hand.", ""]
    hx, w64, w32 = "0x{:02x}", "0x{:016x}ULL", "0x{:08x}u"
    out.append(c_array("uint8_t", "kCamelliaSbox1", sbox, hx))
    out.append(c_array("uint64_t", "kCamelliaSigma", sigma, w64, 3))
    for i, b in enumerate((sb1, sb2, sb3, sb4), 1):
        out.append(c_array("uint8_t", f"kAriaSb{i}", b, hx))
    out.append(c_array("uint8_t", "kAriaC", b"".join(consts), hx))
    out.append(c_array("uint8_t", "kSeedS0", s0, hx))
    out.append(c_array("uint8_t", "kSeedS1", s1, hx))
    out.append(c_array("uint32_t", "kSeedKc", kc, w32, 8))
    for name, vals in (("kDesIp", ip), ("kDesFp", fp), ("kDesE", e), ("kDesP", p), ("kDesPc1", pc1),
                       ("kDesPc2", pc2), ("kDesShifts", shifts)):
        out.append(c_array("uint8_t", name, vals))
    out.append(c_array("uint8_t", "kDesS", [v for sb in sboxes for v in sb]))
    return "\n".join(out)


if __name__ == "__main__":
    sys.stdout.write(main(sys.argv[1:]))
