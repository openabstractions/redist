"""Write the MSI licence page (RTF) from the licence text and any
third-party notices, each notice after a separator line.

  py -3.12 installer/mklicense.py LICENSE OUT.rtf [NOTICE ...]
"""
import sys
from pathlib import Path

HEAD = r"{\rtf1\ansi\deff0{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}\fs18" + "\n"
SEPARATOR = "\n\n" + "-" * 72 + "\n\n"


def rtf(text):
    body = []
    for line in text.replace("\r\n", "\n").split("\n"):
        for ch, esc in (("\\", r"\\"), ("{", r"\{"), ("}", r"\}")):
            line = line.replace(ch, esc)
        body.append("".join(c if ord(c) < 128 else rf"\u{ord(c)}?" for c in line))
    return HEAD + r"\par ".join(body) + "\n}\n"


def page(license_text, notices=()):
    """The licence text, then each notice after a separator line; the
    licence text alone is unchanged."""
    if not notices:
        return license_text
    return SEPARATOR.join([license_text.rstrip("\r\n"), *(notice.strip("\r\n") for notice in notices)]) + "\n"


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help") else 2)
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    notices = [Path(path).read_text(encoding="utf-8") for path in sys.argv[3:]]
    dst.write_text(rtf(page(src.read_text(encoding="utf-8"), notices)), encoding="ascii")
    print(f"{dst} {dst.stat().st_size} bytes from {src}" + "".join(f" + {path}" for path in sys.argv[3:]))
