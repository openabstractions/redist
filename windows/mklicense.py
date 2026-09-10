import sys
from pathlib import Path

HEAD = r"{\rtf1\ansi\deff0{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}\fs18" + "\n"


def rtf(text):
    body = []
    for line in text.replace("\r\n", "\n").split("\n"):
        for ch, esc in (("\\", r"\\"), ("{", r"\{"), ("}", r"\}")):
            line = line.replace(ch, esc)
        body.append("".join(c if ord(c) < 128 else rf"\u{ord(c)}?" for c in line))
    return HEAD + r"\par ".join(body) + "\n}\n"


if __name__ == "__main__":
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.write_text(rtf(src.read_text(encoding="utf-8")), encoding="ascii")
    print(f"{dst} {dst.stat().st_size} bytes from {src}")
